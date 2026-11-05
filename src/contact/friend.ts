import { LONG } from '../session/pb.js'
import { api, site } from '../session/codes.js'
import { err } from '../error.js'
import { fingerprintParams } from '../live/transport.js'
import { FriendRequestStatus } from '../types.js'
import { actionResponse } from '../chat/map.js'
import { listCookieThreads } from '../inbox/thread.js'
import type {
  ActionResult,
  FriendInfo,
  FriendRequestInfo,
  InboxContext,
  InboxListOptions,
  PrivateThread,
  ThreadPeer,
} from '../types.js'

/** P2P 会话线程 → 好友信息 */
function friendOf (thread: PrivateThread): FriendInfo | undefined {
  const peer = thread.peer as ThreadPeer
  if (!peer.uid) return undefined
  return {
    uid: peer.uid,
    ...(peer.secUid ? { secUid: peer.secUid } : {}),
    nickname: peer.nickname ?? '',
    conversationId: thread.threadId,
    conversationShortId: thread.conversationShortId ?? '',
    ...(thread.lastMessage ? { lastMessage: thread.lastMessage } : {}),
    lastMessageTime: thread.lastMessage?.createTime ?? thread.updateTime,
    unreadCount: thread.unreadCount,
  }
}

/** 好友（旧实现：Desktop Cookie 会话 P2P 派生，保留备用） */
export async function listFriendThreads (
  ctx: InboxContext,
  options: InboxListOptions = {},
): Promise<FriendInfo[]> {
  const threads = await listCookieThreads(ctx, options)
  return threads
    .filter((thread) => thread.conversationType === 1 || thread.conversationType === undefined)
    .map(friendOf)
    .filter((friend): friend is FriendInfo => friend != null)
}

/** familiar/list 单行身份 */
interface FamiliarRow {
  uid: string
  secUid?: string
  nickname: string
}

/** familiar/list 响应页（HAR 实测 cursor + has_more 翻页，user_list 为好友行） */
interface FamiliarPage {
  status_code?: number
  user_list?: Array<Record<string, unknown>>
  cursor?: number
  has_more?: boolean
}

/** familiar/list 单行 → 好友身份（remark_name 优先作昵称；缺 uid 丢弃） */
function familiarOf (raw: Record<string, unknown>): FamiliarRow | undefined {
  const uid = String(raw['uid'] ?? '')
  if (!uid) return undefined
  const secUid = String(raw['sec_uid'] ?? '')
  return {
    uid,
    ...(secUid ? { secUid } : {}),
    nickname: String(raw['remark_name'] ?? raw['nickname'] ?? ''),
  }
}

/** GET /aweme/v1/web/familiar/list/ 循环翻页拉全量好友身份 */
async function fetchFamiliarRows (
  ctx: InboxContext,
  options: InboxListOptions = {},
): Promise<FamiliarRow[]> {
  const rows: FamiliarRow[] = []
  const seen = new Set<string>()
  let cursor = options.cursor ?? 0
  for (;;) {
    const params = fingerprintParams(ctx.http.deviceId, ctx.http.guid)
    params.set('cursor', String(cursor))
    params.set('vcd_count', '0')
    params.set('hotsoon_has_more', '0')
    params.set('only_total', '0')
    params.set('count', String(options.count ?? 100))
    params.set('order_by', '1')
    params.set('need_all_friend', '1')
    params.set('recommend_type', '22')
    const res = await ctx.http.json<FamiliarPage>(
      `${site.im}${api.familiar}?${params}`,
      { headers: { Referer: site.im } },
    )
    const page = res.data
    if (Number(page?.status_code ?? 0) !== 0) break
    for (const raw of page.user_list ?? []) {
      const row = familiarOf(raw)
      if (row && !seen.has(row.uid)) {
        seen.add(row.uid)
        rows.push(row)
      }
    }
    if (!page.has_more) break
    const next = Number(page.cursor ?? 0)
    if (!Number.isFinite(next) || next === cursor) break
    cursor = next
  }
  return rows
}

/** 好友列表：真实接口 familiar/list；无会话 ID，按 uid 交叉匹配会话补齐 */
export async function getFriendList (
  ctx: InboxContext,
  options: InboxListOptions = {},
): Promise<FriendInfo[]> {
  const [rows, threads] = await Promise.all([
    fetchFamiliarRows(ctx, options),
    listCookieThreads(ctx, { count: options.count }).catch(() => [] as PrivateThread[]),
  ])
  const byUid = new Map<string, PrivateThread>()
  for (const thread of threads) {
    if (thread.peer.uid && !byUid.has(thread.peer.uid)) byUid.set(thread.peer.uid, thread)
  }
  return rows.map((row) => {
    const thread = byUid.get(row.uid)
    return {
      uid: row.uid,
      ...(row.secUid ? { secUid: row.secUid } : {}),
      nickname: row.nickname,
      // familiar/list 不含会话 ID；无历史会话的好友 conversationId 留空（chatId 形如 1::，仅发送时报错）
      conversationId: thread?.threadId ?? '',
      conversationShortId: thread?.conversationShortId ?? '',
      ...(thread?.lastMessage ? { lastMessage: thread.lastMessage } : {}),
      lastMessageTime: thread?.lastMessage?.createTime ?? thread?.updateTime ?? 0,
      unreadCount: thread?.unreadCount ?? 0,
    }
  })
}

function requestOf (value: Record<string, unknown> | undefined): FriendRequestInfo | undefined {
  if (!value) return undefined
  const applicantUid = String(value['userId'] ?? '')
  if (!applicantUid || applicantUid === '0') return undefined
  const profile = value['profile'] as Record<string, unknown> | undefined
  const ext = value['ext']
  const extRecord = ext && typeof ext === 'object' ? ext as Record<string, string> : undefined
  const nickname = String(profile?.['nickName'] ?? '')
  const avatar = String(profile?.['protrait'] ?? '')
  const requestedAt = String(value['applyTimeSecond'] ?? '')
  const message = String(
    extRecord?.['apply_reason'] ?? extRecord?.['applyReason'] ?? extRecord?.['message'] ?? '',
  )
  return {
    applicantUid,
    status: Number(value['status'] ?? FriendRequestStatus.PENDING) as FriendRequestStatus,
    ...(nickname ? { nickname } : {}),
    ...(avatar ? { avatar } : {}),
    ...(requestedAt && requestedAt !== '0' ? { requestedAt } : {}),
    ...(message ? { message } : {}),
    ...(extRecord ? { ext: extRecord } : {}),
  }
}

/** cmd=20481 好友申请列表 */
export async function getFriendRequests (
  ctx: InboxContext,
  options: { status?: FriendRequestStatus } = {},
): Promise<FriendRequestInfo[]> {
  const requests: FriendRequestInfo[] = []
  let cursor = '0'
  for (;;) {
    const decoded = await ctx.transport.sendCookieProto(
      20481,
      0,
      '/v1/friend/get_receive_apply_list',
      {
        getFriendReceiveApplyList: {
          cursor: LONG.fromString(cursor),
          limit: LONG.fromString('100'),
          getTotalCount: true,
          status: options.status ?? FriendRequestStatus.PENDING,
        },
      },
      ctx.deviceId,
    )
    const result = actionResponse(decoded)
    if (result.statusCode !== 0) return err(decoded)
    const body = (decoded['body'] as Record<string, unknown> | undefined)?.[
      'getFriendReceiveApplyList'
    ] as {
      nextCursor?: string | number | { toString (): string }
      hasMore?: boolean
      userList?: Array<Record<string, unknown>>
    } | undefined
    for (const raw of body?.userList ?? []) {
      const request = requestOf(raw)
      if (request) requests.push(request)
    }
    if (!body?.hasMore) return requests
    const next = String(body.nextCursor ?? '')
    if (!next) return requests
    cursor = next
  }
}

/** cmd=2049 审批好友申请 */
export async function reviewFriendRequest (
  ctx: InboxContext,
  applicantUid: string,
  status: FriendRequestStatus.APPROVED | FriendRequestStatus.REJECTED,
): Promise<ActionResult> {
  const decoded = await ctx.transport.sendCookieProto(
    2049,
    0,
    '/v1/friend/reply_apply',
    {
      replyFriendApply: {
        userId: [LONG.fromString(applicantUid)],
        attitude: status,
        ext: {},
      },
    },
    ctx.deviceId,
  )
  return actionResponse(decoded, 'replyFriendApply')
}
