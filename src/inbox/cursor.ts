import { LONG } from '../session/pb.js'
import type { ActionResult, ConversationAddress, InboxContext, MinIndexRow, ReadIndexRow } from '../types.js'
import { actionResponse } from '../chat/map.js'

/** cmd=2000 get_read_index:按会话查各成员已读游标 */
export async function getReadIndex (
  ctx: InboxContext,
  item: ConversationAddress,
): Promise<ReadIndexRow[]> {
  const decoded = await ctx.transport.sendCookieProto(
    2000,
    item.inboxType ?? 0,
    '/v3/conversation/get_read_index',
    {
      getReadIndex: {
        conversationShortId: LONG.fromString(item.conversationShortId || '0'),
        conversationType: item.conversationType,
        conversationId: item.conversationId,
      },
    },
    ctx.deviceId,
  )
  const list = ((decoded['body'] as { getReadIndex?: { readIndexList?: unknown[] } } | undefined)
    ?.getReadIndex?.readIndexList ?? []) as Record<string, unknown>[]
  return list.map((raw) => ({
    uid: String(raw['uid'] ?? ''),
    readIndex: Number(raw['readIndex'] ?? 0),
    ...(raw['extra'] != null ? { extra: Number(raw['extra']) } : {}),
  }))
}

/** cmd=2038 batch_get_conversation_participants_readindex:批量查所有成员已读游标（HAR 响应为空 body） */
export async function batchReadIndex (
  ctx: InboxContext,
  item: ConversationAddress,
): Promise<ActionResult> {
  const decoded = await ctx.transport.sendCookieProto(
    2038,
    item.inboxType ?? 1,
    '/v1/conversation/batch_get_conversation_participants_readindex',
    {
      getConversationParticipantsReadIndex: {
        conversationId: item.conversationId,
        conversationShortId: LONG.fromString(item.conversationShortId || '0'),
        getUserReadIndex: 1,
      },
    },
    ctx.deviceId,
  )
  return actionResponse(decoded, 'getConversationParticipantsReadIndex')
}

/** cmd=2001 get_min_index:按会话查各成员最小同步游标（增量拉取起点） */
export async function getMinIndex (
  ctx: InboxContext,
  item: ConversationAddress,
): Promise<MinIndexRow[]> {
  const decoded = await ctx.transport.sendCookieProto(
    2001,
    item.inboxType ?? 0,
    '/v3/conversation/get_min_index',
    {
      getMinIndex: {
        conversationShortId: LONG.fromString(item.conversationShortId || '0'),
        conversationType: item.conversationType,
        conversationId: item.conversationId,
      },
    },
    ctx.deviceId,
  )
  const list = ((decoded['body'] as { getMinIndex?: { minIndexList?: unknown[] } } | undefined)
    ?.getMinIndex?.minIndexList ?? []) as Record<string, unknown>[]
  return list.map((raw) => ({
    uid: String(raw['uid'] ?? ''),
    minIndex: Number(raw['minIndex'] ?? 0),
  }))
}
