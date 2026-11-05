import { LONG } from '../session/pb.js'
import type { InboxContext, MarkReadItem, ModifyReactionItem, RecallItem, RecallResult } from '../types.js'

/** cmd=705, /v1/message/set_property — 消息表情回应（operation 0=添加 1=移除） */
export async function modifyReaction (
  ctx: InboxContext,
  options: ModifyReactionItem,
): Promise<{ statusCode: number; statusMsg: string }> {
  const decoded = await ctx.transport.sendCookieProto(
    705,
    options.inboxType ?? 0,
    '/v1/message/set_property',
    {
      modifyMessageProperty: {
        propertyList: [{
          conversationId: options.conversationId,
          conversationType: options.conversationType ?? 1,
          conversationShortId: LONG.fromString(options.conversationShortId || '0'),
          serverMessageId: LONG.fromString(options.serverMessageId),
          clientMessageId: '',
          modifyPropertyContent: [{
            operation: options.enabled ? 0 : 1,
            key: `se:${options.emoji}`,
            value: '',
            idempotentId: options.operatorUid,
          }],
        }],
        ticket: '',
      },
    },
    ctx.deviceId,
  )
  const envelopeStatus = Number(decoded['statusCode'] ?? 0)
  // statusCode=1 表示已应用（幂等），对齐 douyin-im 视为成功
  return {
    statusCode: envelopeStatus === 1 ? 0 : envelopeStatus,
    statusMsg: String(decoded['errorDesc'] ?? ''),
  }
}

/** 会话标记已读：cmd=2002 mark_conversation_read（对齐 native rawMarkConversationRead，body oneof tag 604） */
export async function markConversationRead (
  ctx: InboxContext,
  options: MarkReadItem,
): Promise<{ statusCode: number; statusMsg: string }> {
  const send = async (endpoint: string): Promise<Record<string, unknown>> =>
    ctx.transport.sendCookieProto(
      2002,
      options.inboxType ?? 1,
      endpoint,
      {
        markConversationRead: {
          conversationId: options.conversationId,
          conversationShortId: LONG.fromString(options.conversationShortId || '0'),
          conversationType: options.conversationType ?? 1,
          readMessageIndex: LONG.fromString(options.readMessageIndex ?? '0'),
          readMessageIndexV2: LONG.fromString(options.readMessageIndexV2 ?? '0'),
          convUnreadCount: LONG.fromString('0'),
          totalUnreadCount: LONG.fromString('0'),
          readBadgeCount: 0,
          serverMessageId: LONG.fromString(options.serverMessageId ?? '0'),
          ticket: '',
        },
      },
      ctx.deviceId,
    )

  // 国内 imapi3-normal 走 /v1；国际版参考路径为 /v3，状态非 0 时降级重试一次
  let decoded = await send('/v1/conversation/mark_read')
  if (Number(decoded['statusCode'] ?? 0) !== 0 && Number(decoded['statusCode'] ?? 0) !== 1) {
    decoded = await send('/v3/conversation/mark_read')
  }
  const envelopeStatus = Number(decoded['statusCode'] ?? 0)
  // statusCode=1 表示已应用（幂等），对齐 douyin-im 视为成功
  return {
    statusCode: envelopeStatus === 1 ? 0 : envelopeStatus,
    statusMsg: String(decoded['errorDesc'] ?? ''),
  }
}

/** cmd=702, /v1/message/recall — 撤回已投递消息 */
export async function recall (
  ctx: InboxContext,
  options: RecallItem,
): Promise<RecallResult> {
  const decoded = await ctx.transport.sendCookieProto(
    702,
    options.inboxType ?? 0,
    '/v1/message/recall',
    {
      recallMessage: {
        conversationId: options.conversationId,
        conversationShortId: LONG.fromString(options.conversationShortId || '0'),
        conversationType: options.conversationType ?? 1,
        serverMessageId: LONG.fromString(options.serverMessageId),
      },
    },
    ctx.deviceId,
  )
  const envelopeStatus = Number(decoded['statusCode'] ?? 0)
  const body = decoded['body'] as Record<string, unknown> | undefined
  const recallBody = body?.['recallMessage'] as { status?: number } | undefined
  const actionStatus = recallBody?.status ?? 0
  return {
    statusCode: envelopeStatus || actionStatus,
    statusMsg: String(decoded['errorDesc'] ?? ''),
    recalled: envelopeStatus === 0 && actionStatus === 0,
  }
}
