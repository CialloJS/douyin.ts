import { listStrangerThreads } from '../inbox/thread.js'
import type { InboxContext, PrivateThread, StrangerInfo, ThreadPeer } from '../types.js'

/** 陌生人会话线程 → 陌生人信息 */
function strangerOf (thread: PrivateThread): StrangerInfo | undefined {
  const peer = thread.peer as ThreadPeer
  if (!peer.uid) return undefined
  return {
    uid: peer.uid,
    ...(peer.secUid ? { secUid: peer.secUid } : {}),
    ...(peer.nickname ? { nickname: peer.nickname } : {}),
    conversationId: thread.threadId,
    conversationShortId: thread.conversationShortId ?? '',
    ...(thread.lastMessage ? { lastMessage: thread.lastMessage } : {}),
    lastMessageTime: thread.lastMessage?.createTime ?? thread.updateTime,
    unreadCount: thread.unreadCount,
  }
}

/** 陌生人会话列表 */
export async function getStrangerList (
  ctx: InboxContext,
): Promise<StrangerInfo[]> {
  const threads = await listStrangerThreads(ctx)
  return threads
    .map(strangerOf)
    .filter((stranger): stranger is StrangerInfo => stranger !== undefined)
}
