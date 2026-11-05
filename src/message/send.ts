import { sendCmd411 } from '../live/transport.js'
import { buildAtAllTextContent, buildReplyPayload, buildDesktopTextContent, textWithAts } from './content.js'
import { send } from './core.js'
import type { SendContext } from './core.js'
import type {
  ConversationAddress,
  ReplyOptions,
  SendMessageResponse,
  TextMention,
  VoiceCallResult,
} from '../types.js'

export type { SendContext } from './core.js'
export { send } from './core.js'
export { sendBody, sendImage, sendVideo, sendFile, sendShare, sendUserCard } from './payload.js'
export { sendMergeForward, buildForwardNodes } from './forward.js'

/** 发送文本（可带 @ 提及：content richTextInfos + mentionedUsers 字段） */
export async function sendText (
  ctx: SendContext,
  address: ConversationAddress,
  text: string,
  mentions?: TextMention[],
): Promise<SendMessageResponse> {
  return send(ctx, {
    ...address,
    content: mentions?.length ? buildDesktopTextContent(text, mentions) : text,
    messageType: 7,
    ...(mentions?.length ? { mentionedUsers: [...new Set(mentions.map(m => m.uid))] } : {}),
  })
}

/**
 * 上报输入状态（让对方显示「正在输入…」）。
 * 走 Android Frontier WS cmd=411（接收侧是 WS 504 推送）。
 * 无确认回执（fire-and-forget），返回 true 仅表示帧已发出。
 */
export async function sendTyping (
  ctx: SendContext,
  address: ConversationAddress,
  typing: boolean,
): Promise<boolean> {
  return sendCmd411({
    userId: ctx.userId,
    cookies: ctx.cookies,
    conversationId: address.conversationId,
    conversationShortId: address.conversationShortId || '0',
    conversationType: address.conversationType ?? 1,
    typing,
  })
}

/**
 * 发起语音通话——未支持。
 * 实测证伪（保留签名便于收敛）：cmd2011/2012 走 Android WS 服务端仅回框架 ACK 无业务响应；
 * imapi3 HTTP 通道路由表（StatusCodeRouteNotFound 全量列举）无任何 voip/voice 命令；
 * 官方桌面端 VOIP 走独立未公开端点（需 App 专属签名）。不再发起任何网络请求。
 */
export async function startVoiceCall (
  ctx: SendContext,
  address: ConversationAddress,
  calleeUid: string,
): Promise<VoiceCallResult> {
  ctx.log.warn(`语音通话未支持: 被叫=${calleeUid} 会话=${address.conversationShortId || '-'}`)
  return { statusCode: -1, checkMessage: '服务端无 VOIP 通道' }
}

/** 引用回复：正文 desktop 文本模板 + refMsgInfo（cmd100 field 11）；atAll/ats 时正文换 @ 模板并透传 f9 */
export async function reply (ctx: SendContext, options: ReplyOptions): Promise<SendMessageResponse> {
  const payload = buildReplyPayload({
    text: options.text,
    referencedMessageId: options.referencedMessageId,
    referencedMessageType: options.referencedMessageType,
    referencedUid: options.referencedUid,
    ...(options.referencedSecUid ? { referencedSecUid: options.referencedSecUid } : {}),
    ...(options.nickname ? { nickname: options.nickname } : {}),
    ...(options.referencedText ? { referencedText: options.referencedText } : {}),
    ...(options.rootMessageId ? { rootMessageId: options.rootMessageId } : {}),
    ...(options.rootMessageConvIndex ? { rootMessageConvIndex: options.rootMessageConvIndex } : {}),
  })
  // @所有人/@提及 的引用回复正文走对应模板（atAll 优先）；纯文本引用保持 buildReplyPayload 默认
  const content = options.atAll
    ? buildAtAllTextContent(options.text)
    : options.ats?.length
      ? textWithAts(options.text, options.ats, options.conversationId).content
      : payload.content
  const { ats, ...sendOptions } = options
  return send(ctx, {
    ...sendOptions,
    content,
    messageType: 7,
    reference: payload.reference,
    ...(ats?.length ? { mentionedUsers: [...new Set(ats.map(m => m.uid))] } : {}),
  })
}
