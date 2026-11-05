import { parseBody } from './parse.js'
import type { InboundMessage, PushMessage } from '../types.js'

export { extractAndroidPushes } from './push.js'
export { extractReactions, toReadEvent, toStatusEvent, toVoipCall } from './event.js'

/** 原始推送 → 业务入站消息（平铺消息体：type 判别 + text 展示文本） */
export function toInboundMessage (push: PushMessage): InboundMessage {
  // raw 以 push 原样为准（parseBody 的 raw 仅兜底，交集后 PushMessage.raw 必为对象）
  return {
    ...parseBody(push.content, push.messageType),
    ...push,
  }
}
