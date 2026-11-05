import { err } from '../error.js'
import type { BotMessage, ConversationAddress, PushMessage, SendMessageReference } from '../types.js'
import { buildReference } from '../message/content.js'

/** chatId：`type:shortId:conversationId` 的不透明串，格式不承诺稳定 */
export function chatIdOf (src: PushMessage | { conversationId: string; conversationShortId: string; conversationType: number }): string {
  // 盖楼消息：type=50 哨兵，会话位直接装 threadId 全串；回传发送走普通 HTTP（不支持进楼）
  if ('threadId' in src && src.threadId) {
    return `50:${src.threadShortId ?? src.conversationShortId ?? ''}:${src.threadId}`
  }
  return `${src.conversationType}:${src.conversationShortId}:${src.conversationId}`
}

export function toAddress (chatId: string): ConversationAddress {
  // conversationId 本身含冒号（私聊 threadId 形如 0:1:uid:uid），首两段之外全部归属 conversationId
  const [type, shortId, ...rest] = chatId.split(':')
  const conversationId = rest.join(':')
  if (!type || !shortId || !conversationId) return err({ chatId })
  return { conversationId, conversationShortId: shortId, conversationType: Number(type) as 1 | 2 | 50 }
}

/** 由收到的消息提取引用元数据：任意消息类型均可被引用，类型原样透传 */
export function referenceOf (msg: BotMessage): SendMessageReference {
  return buildReference({
    referencedMessageId: msg.serverMessageId ?? '',
    referencedMessageType: msg.messageType,
    referencedUid: msg.senderUid,
    referencedSecUid: msg.senderSecUid,
    nickname: msg.senderNickname,
    referencedText: msg.text,
    rootMessageId: msg.reference?.rootMessageId,
  })
}

/** 可进昵称缓存的条目（好友/陌生人/群成员/申请列表的公共形状） */
export type NickEntry = { uid: string; nickname?: string; alias?: string }
