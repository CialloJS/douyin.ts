import { LONG } from '../session/pb.js'
import { err } from '../error.js'
import type { InboxContext, InboxListOptions, PrivateThread } from '../types.js'
import { dedupeThreads, mapProtoConversation, mapProtoConversationMeta } from '../chat/map.js'

const retryPause = 1000

function sleep (ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/** 服务端偶发 StatusCodeRPCTimeout(500)，重试缓解；三次仍失败交回上游响应或原生异常 */
async function fetchThreads (
  ctx: InboxContext,
  inboxType: number,
  limit: number,
  cursor: number,
): Promise<Record<string, unknown>> {
  let last: Record<string, unknown> | undefined
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await ctx.transport.sendCookieProto(
        203,
        inboxType,
        '/v2/message/get_by_user_init',
        { inbox: { convLimit: limit, msgLimit: limit, cursor } },
        ctx.deviceId,
      )
      if (Number(res['statusCode'] ?? 0) === 0) return res
      last = res
    } catch (error) {
      // 网络异常不在 SDK 层包装，重试耗尽后原样冒泡
      if (attempt === 2) throw error
    }
    if (attempt < 2) await sleep(retryPause)
  }
  return err(last)
}

/** Desktop Cookie cmd=203。实测 inboxType=1 返回群聊及普通私信;不依赖 Creator IM token。循环翻页拉全量。 */
export async function listCookieThreads (
  ctx: InboxContext,
  options: InboxListOptions & { inboxType?: number } = {},
): Promise<PrivateThread[]> {
  const limit = options.count ?? 20
  const threads: PrivateThread[] = []
  // 翻页按上游 hasMore 终止，上游未给出可推进的 cursor 时也结束，不做重复判断
  for (let cursor = options.cursor ?? 0; ; ) {
    const decoded = await fetchThreads(ctx, options.inboxType ?? 1, limit, cursor)
    const body = decoded['body'] as Record<string, unknown> | null
    const inbox = body?.['inbox'] as {
      messages?: unknown[]
      conversations?: unknown[]
      hasMore?: boolean | number
      cursor?: string | number | { toString (): string }
    } | null
    const rawMessages = (inbox?.messages ?? []) as Record<string, unknown>[]
    const rawConversations = (inbox?.conversations ?? []) as Record<string, unknown>[]
    threads.push(...(rawConversations.length > 0
      ? rawConversations.map((conversation) =>
        mapProtoConversationMeta(conversation, rawMessages, ctx.platformUid),
      )
      : rawMessages.map((message) => mapProtoConversation(message, ctx.platformUid))))
    if (!inbox?.hasMore) break
    const next = Number(inbox.cursor ?? '')
    if (!Number.isFinite(next)) break
    cursor = next
  }
  return dedupeThreads(threads)
}

/** cmd=2047, /v1/message/get_recent_stranger_message — 陌生人消息（Desktop Cookie 通道；接口无分页字段） */
export async function listStrangerThreads (
  ctx: InboxContext,
): Promise<PrivateThread[]> {
  const decoded = await ctx.transport.sendCookieProto(
    2047,
    1,
    '/v1/message/get_recent_stranger_message',
    {
      getRecentStrangerMessage: {
        latestStrangerVersion: LONG.fromString('0'),
        earliestStrangerVersion: LONG.fromString('0'),
        source: 'code_up',
        newUser: 0,
        bizInfo: '',
      },
    },
    ctx.deviceId,
  )

  if (Number(decoded['statusCode'] ?? 0) !== 0) return err(decoded)

  const body = decoded['body'] as Record<string, unknown> | null
  const page = body?.['getRecentStrangerMessage'] as { messages?: unknown[] } | null
  const rows = (page?.messages ?? []) as Record<string, unknown>[]
  const rawMessages = rows.flatMap(row => (row['messages'] ?? []) as Record<string, unknown>[])
  return dedupeThreads(rawMessages.map(message => mapProtoConversation(message, ctx.platformUid)))
}
