import { LONG } from '../session/pb.js'
import { actionResponse } from '../chat/map.js'
import type { ActionResult, ClientAckItem, InboxContext, StrangerListOptions, UserMessageQuery } from '../types.js'

/** cmd=2048 get_user_message:按 uid 消息区间查询（HAR 响应字段全 0，返回原始结构） */
export async function getUserMessage (
  ctx: InboxContext,
  req: UserMessageQuery = {},
): Promise<Record<string, unknown>> {
  const decoded = await ctx.transport.sendCookieProto(
    2048,
    req.inboxType ?? 0,
    '/v1/message/get_user_message',
    {
      getUserMessage: {
        startIndex: LONG.fromString(req.startIndex ?? '0'),
        messageType: LONG.fromString(req.messageType ?? '0'),
        endIndex: LONG.fromString(req.endIndex ?? '0'),
        cursor: req.cursor ?? '',
      },
    },
    ctx.deviceId,
  )
  return ((decoded['body'] as Record<string, unknown> | undefined)?.['getUserMessage'] ??
    {}) as Record<string, unknown>
}

/** cmd=2010 client/ack:客户端消息回执（type=500 到达/已读确认，响应仅 envelope 成功帧） */
export async function clientAck (
  ctx: InboxContext,
  item: ClientAckItem,
): Promise<ActionResult> {
  const decoded = await ctx.transport.sendCookieProto(
    2010,
    item.inboxType ?? 0,
    '/v1/client/ack',
    {
      clientAck: {
        serverMessageId: LONG.fromString(item.serverMessageId),
        messageType: item.messageType ?? 500,
        status: item.status ?? 0,
        ...(item.clientMessageId
          ? { clientMessageId: LONG.fromString(item.clientMessageId) }
          : {}),
        ...(item.conversationShortId
          ? { conversationShortId: LONG.fromString(item.conversationShortId) }
          : {}),
        ...(item.count != null ? { count: item.count } : {}),
      },
    },
    ctx.deviceId,
  )
  return actionResponse(decoded)
}

/** cmd=1001 stranger/get_conversation_list:陌生人会话列表（实测服务端限流 409，错因在 statusMsg） */
export async function strangerConversations (
  ctx: InboxContext,
  req: StrangerListOptions = {},
): Promise<ActionResult> {
  const decoded = await ctx.transport.sendCookieProto(
    1001,
    req.inboxType ?? 0,
    '/v1/stranger/get_conversation_list',
    {
      strangerConversationList: {
        cursor: LONG.fromString(String(req.cursor ?? '0')),
        source: req.source ?? 1,
        scene: req.scene ?? 1,
      },
    },
    ctx.deviceId,
  )
  return actionResponse(decoded)
}
