import { err } from '../error.js'
import { mapProtoConversationListItem } from './map.js'
import type { GroupInfo, InboxContext, InboxListOptions } from '../types.js'

/**
 * cmd=2006 会话列表：响应不回传翻页游标，服务端按请求 cursor 做 offset 式推进，
 * 不足一页即到底；忽略 cursor 时会恒回同一批，因此按 shortId 去重。
 */
async function collect (
  ctx: InboxContext,
  options: InboxListOptions,
  native: boolean,
): Promise<GroupInfo[]> {
  const all: GroupInfo[] = []
  const seen = new Set<string>()
  let cursor = options.cursor ?? 0
  for (;;) {
    const limit = options.count ?? 20
    const request = { conversationList: { listType: 1, cursor, sortType: 2, limit } }
    const decoded = native
      ? await ctx.transport.sendNativeProto(2006, 0, '/v1/conversation/list', request, ctx.deviceId)
      : await ctx.transport.sendCookieProto(2006, 0, '/v1/conversation/list', request, ctx.deviceId)
    const statusCode = Number(decoded['statusCode'] ?? 0)
    if (statusCode !== 0) return err(decoded)
    const list = (decoded['body'] as Record<string, unknown> | null)?.['conversationList'] as {
      conversations?: Array<Record<string, unknown>>
    } | undefined
    const conversations = list?.conversations ?? []
    const fresh = conversations.filter((conversation) => {
      const id = String(conversation['conversationShortId'] ?? '')
      if (!id || seen.has(id)) return false
      seen.add(id)
      return true
    })
    all.push(...fresh.map(mapProtoConversationListItem))
    if (conversations.length < limit || fresh.length === 0) break
    cursor += conversations.length
  }
  return all
}

/** Desktop Cookie 通道会话列表 */
export function listConversations (
  ctx: InboxContext,
  options: InboxListOptions = {},
): Promise<GroupInfo[]> {
  return collect(ctx, options, false)
}

/** 旧 Cookie 通道群列表（备用；群列表主用 listNativeGroups） */
export async function listConversationsByCookie (
  ctx: InboxContext,
  options: InboxListOptions = {},
): Promise<GroupInfo[]> {
  const conversations = await listConversations(ctx, options)
  return conversations.filter((conversation) => conversation.isGroup)
}

/** 群列表：原生通道 imapi.douyin.com（对齐官方 PC 群列表） */
export async function listNativeGroups (
  ctx: InboxContext,
  options: InboxListOptions = {},
): Promise<GroupInfo[]> {
  const conversations = await collect(ctx, options, true)
  return conversations.filter((conversation) => conversation.isGroup)
}

/** 群列表：原生通道全量群会话 */
export function getGroupList (
  ctx: InboxContext,
  options: InboxListOptions = {},
): Promise<GroupInfo[]> {
  return listNativeGroups(ctx, options)
}
