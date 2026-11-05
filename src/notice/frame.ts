import { decodeWire, decodeWireTree } from '../live/wire.js'
import { commandPayload, fieldString, messageChildren } from './field.js'
import type { NoticeEvent, RequestEvent } from '../types.js'

/** Android Frontier 原生通知/请求事件（501 已读、502 会话更新、507 好友事件、504 输入状态） */
export function extractAndroidNotices (payload: Uint8Array): (NoticeEvent | RequestEvent)[] {
  const top = decodeWire(payload)
  const tree = decodeWireTree(payload)
  const envelopes = messageChildren(top, 8)
  if (messageChildren(top, 6).length > 0) envelopes.push(top)
  const notices: (NoticeEvent | RequestEvent)[] = []
  for (const envelope of envelopes) {
    for (const body of messageChildren(envelope, 6)) {
      for (const read of messageChildren(body, 501)) {
        notices.push({
          type: 'conversation.read',
          conversationId: fieldString(read, 1) ?? '',
          conversationType: Number(fieldString(read, 2) ?? 0),
          readMessageIndex: fieldString(read, 3) ?? '0',
          readMessageIndexV2: fieldString(read, 4) ?? '0',
          raw: { transport: 'android-frontier', wireTree: tree },
        })
      }
      for (const updated of messageChildren(body, 502)) {
        for (const conversation of messageChildren(updated, 1)) {
          notices.push({
            type: 'conversation.update',
            conversationId: fieldString(conversation, 1) ?? '',
            conversationType: Number(fieldString(conversation, 3) ?? 0),
            raw: { transport: 'android-frontier', wireTree: tree },
          })
        }
      }
      for (const friend of messageChildren(body, 507)) {
        const messageType = Number(fieldString(friend, 1) ?? 0)
        const fromUid = fieldString(friend, 2) ?? ''
        const toUid = fieldString(friend, 3) ?? ''
        const peerUid = fromUid || toUid
        const content = fieldString(friend, 4)
        if (messageType === 1 && peerUid) {
          notices.push({
            type: 'friend.request',
            applicantUid: peerUid,
            ...(fromUid ? { fromUid } : {}),
            ...(toUid ? { toUid } : {}),
            ...(content ? { content } : {}),
            raw: { transport: 'android-frontier', wireTree: tree },
          })
        } else if ((messageType === 2 || messageType === 3) && peerUid) {
          notices.push({
            type: messageType === 3 ? 'friend.increase' : 'friend.decrease',
            peerUid,
            ...(fromUid ? { fromUid } : {}),
            ...(toUid ? { toUid } : {}),
            ...(content ? { content } : {}),
            raw: { transport: 'android-frontier', wireTree: tree },
          })
        }
      }
      for (const typing of messageChildren(body, 504)) {
        const content = commandPayload(fieldString(typing, 8) ?? '')
        const inputStatus = Number(content?.['input_status'] ?? -1)
        if (inputStatus < 0) continue
        const conversationId = fieldString(typing, 4) ?? ''
        const peerUid = fieldString(typing, 2) ?? ''
        const senderUid = fieldString(typing, 22) ?? peerUid
        if (!conversationId && !peerUid) continue
        const peerSecUid = fieldString(typing, 3)
        notices.push({
          type: 'conversation.typing',
          conversationId,
          peerUid,
          ...(peerSecUid ? { peerSecUid } : {}),
          senderUid,
          typing: inputStatus === 1,
          raw: { transport: 'android-frontier', wireTree: tree },
        })
      }
    }
  }
  return notices
}
