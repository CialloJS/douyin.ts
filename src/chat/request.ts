import { LONG } from '../session/pb.js'
import { err } from '../error.js'
import { GroupJoinRequestStatus } from '../types.js'
import { actionResponse } from './map.js'
import type { ActionResult, GroupJoinRequestInfo, InboxContext } from '../types.js'

/** 入群申请行映射；缺关键字段的行直接丢弃 */
function requestOf (value: Record<string, unknown> | undefined): GroupJoinRequestInfo | undefined {
  if (!value) return undefined
  const requestId = String(value['applyId'] ?? '')
  const applicantUid = String(value['userId'] ?? '')
  const groupShortId = String(value['convShortId'] ?? '')
  if (!requestId || !applicantUid || !groupShortId) return undefined
  const applicantSecUid = String(value['secUid'] ?? '')
  const reason = String(value['applyReason'] ?? '')
  const inviterUid = String(value['inviteUserId'] ?? '')
  const inviterSecUid = String(value['secInviteUid'] ?? '')
  const createdAt = String(value['createTime'] ?? '')
  const modifiedAt = String(value['modifyTime'] ?? '')
  const moderatorUid = String(value['modifyUser'] ?? '')
  const ext = value['ext']
  return {
    requestId,
    applicantUid,
    groupShortId,
    conversationType: Number(value['conversationType'] ?? 2),
    status: Number(value['applyStatus'] ?? GroupJoinRequestStatus.PENDING) as GroupJoinRequestStatus,
    ...(applicantSecUid ? { applicantSecUid } : {}),
    ...(reason ? { reason } : {}),
    ...(inviterUid && inviterUid !== '0' ? { inviterUid } : {}),
    ...(inviterSecUid ? { inviterSecUid } : {}),
    ...(createdAt && createdAt !== '0' ? { createdAt } : {}),
    ...(modifiedAt && modifiedAt !== '0' ? { modifiedAt } : {}),
    ...(moderatorUid && moderatorUid !== '0' ? { moderatorUid } : {}),
    ...(ext && typeof ext === 'object' ? { ext: ext as Record<string, string> } : {}),
  }
}

/** cmd=2027 入群申请列表 */
export async function getGroupJoinRequests (
  ctx: InboxContext,
  options: { conversationShortId?: string } = {},
): Promise<GroupJoinRequestInfo[]> {
  const requests: GroupJoinRequestInfo[] = []
  let cursor = '0'
  for (;;) {
    const decoded = await ctx.transport.sendCookieProto(
      2027,
      1,
      '/v1/conversation/get_audit_list',
      { getConversationAuditList: { cursor: LONG.fromString(cursor), limit: 100 } },
      ctx.deviceId,
    )
    const result = actionResponse(decoded)
    if (result.statusCode !== 0) return err(decoded)
    const body = (decoded['body'] as Record<string, unknown> | undefined)?.[
      'getConversationAuditList'
    ] as {
      applyInfoList?: Array<Record<string, unknown>>
      nextCursor?: string | number | { toString (): string }
      hasMore?: boolean
    } | undefined
    for (const raw of body?.applyInfoList ?? []) {
      const request = requestOf(raw)
      if (request && (!options.conversationShortId || request.groupShortId === options.conversationShortId)) {
        requests.push(request)
      }
    }
    if (!body?.hasMore) return requests
    const next = String(body.nextCursor ?? '')
    if (!next) return requests
    cursor = next
  }
}

/** cmd=2025 审批入群申请 */
export async function reviewGroupJoinRequest (
  ctx: InboxContext,
  requestId: string,
  status: GroupJoinRequestStatus.APPROVED | GroupJoinRequestStatus.REJECTED,
): Promise<ActionResult & { request?: GroupJoinRequestInfo }> {
  const decoded = await ctx.transport.sendCookieProto(
    2025,
    1,
    '/v1/conversation/ack_apply',
    {
      ackConversationApply: {
        applyId: LONG.fromString(requestId),
        applyStatus: status,
        bizExt: {},
      },
    },
    ctx.deviceId,
  )
  const result = actionResponse(decoded, 'ackConversationApply')
  const payload = decoded['body'] as Record<string, unknown> | undefined
  const body = payload?.['ackConversationApply'] as {
    applyInfo?: Record<string, unknown>
  } | undefined
  const request = requestOf(body?.applyInfo)
  return { ...result, ...(request ? { request } : {}) }
}
