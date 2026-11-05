import {
  asRecord,
  commandPayload,
  firstString,
  noticeUsers,
  uidList,
} from './field.js'
import type {
  GroupMemberDecreaseSource,
  GroupMemberIncreaseSource,
  NoticeEvent,
  NoticeUser,
  PushMessage,
  RequestEvent,
} from '../types.js'

export { fieldString, collectKeyValues, protectBigInt } from './field.js'
export { extractAndroidNotices } from './frame.js'

const commandTypes = new Set([
  40001, 50001, 50002, 50003, 50004, 50005, 50010, 50011, 50012, 50013,
  50014, 50015, 50016, 50017, 60001, 70001, 70002, 80001, 80002, 80003,
  80004, 80005, 90001, 90002,
])

const increaseTypes = new Map<number, GroupMemberIncreaseSource>([
  [100100, 'invite'],
  [100101, 'command'],
  [100102, 'qrcode'],
  [100107, 'duoshan'],
  [100109, 'apply'],
  [100111, 'search'],
  [100112, 'activity'],
  [100113, 'face-to-face'],
  [100114, 'circle'],
  // 「{1}通过{0}分享的群二维码加入了群聊」（分享者分享二维码，入群者扫码）
  [100128, 'qrcode'],
  // 「你邀请{1}加入了群聊」/「{0}邀请你加入了群聊」两种视角同型，均为邀请入群
  [100140, 'invite'],
])

const decreaseTypes = new Map<number, GroupMemberDecreaseSource>([
  [100104, 'kick'],
  [100105, 'leave'],
])

function aweTypeOf (payload: Record<string, unknown>): number {
  return Number(payload['aweType'] ?? payload['awe_type'] ?? 0)
}

function groupMemberIncrease (push: PushMessage, payload?: Record<string, unknown>): NoticeEvent | undefined {
  if (push.conversationType !== 2 || !payload) return undefined
  const source = increaseTypes.get(aweTypeOf(payload))
  if (!source) return undefined
  const members = noticeUsers(payload['passive_users'] ?? payload['passiveUsers'])
  if (members.length === 0) return undefined
  return {
    type: 'group.member-increase',
    conversationId: push.conversationId,
    conversationShortId: push.conversationShortId || push.conversationId,
    conversationType: 2,
    source,
    members,
    operators: noticeUsers(payload['active_users'] ?? payload['activeUsers']),
    raw: push.raw,
  }
}

function groupMemberDecrease (push: PushMessage, payload?: Record<string, unknown>): NoticeEvent | undefined {
  if (push.conversationType !== 2 || !payload) return undefined
  const source = decreaseTypes.get(aweTypeOf(payload))
  if (!source) return undefined
  const activeUsers = noticeUsers(payload['active_users'] ?? payload['activeUsers'])
  const passiveUsers = noticeUsers(payload['passive_users'] ?? payload['passiveUsers'])
  const members = source === 'leave' ? activeUsers : passiveUsers
  if (members.length === 0) return undefined
  return {
    type: 'group.member-decrease',
    conversationId: push.conversationId,
    conversationShortId: push.conversationShortId || push.conversationId,
    conversationType: 2,
    source,
    members,
    // 主动退群没有另一位操作者；SDK 层会把 member 自身投影为 operator。
    operators: source === 'leave' ? [] : activeUsers,
    raw: push.raw,
  }
}

/** 群名/头像/管理员/解散：aweType 决定语义，载荷字段同源 */
function groupMeta (push: PushMessage, payload?: Record<string, unknown>): NoticeEvent | undefined {
  if (push.conversationType !== 2 || !payload) return undefined
  const aweType = aweTypeOf(payload)
  const base = {
    conversationId: push.conversationId,
    conversationShortId: push.conversationShortId || push.conversationId,
    conversationType: 2 as const,
    operators: noticeUsers(payload['active_users'] ?? payload['activeUsers']),
    raw: push.raw,
  }
  if (aweType === 100110) {
    const members = noticeUsers(payload['passive_users'] ?? payload['passiveUsers'])
    if (members.length === 0) return undefined
    return { type: 'group.admin', ...base, members, enabled: true }
  }
  if (aweType === 100106) {
    const name = firstString(payload, ['new_name', 'newName', 'conversation_name', 'conversationName', 'name'])
    return { type: 'group.name-change', ...base, ...(name ? { name } : {}) }
  }
  if (aweType === 100115) {
    const avatar = firstString(payload, ['new_avatar', 'newAvatar', 'avatar_url', 'avatarUrl', 'avatar'])
    return { type: 'group.avatar-change', ...base, ...(avatar ? { avatar } : {}) }
  }
  if (aweType === 100124) {
    // 「群聊已被解散」：payload 只有 locale_resources，无 active_users，解散者即推送发送方
    const uid = push.senderUid || noticeUsers(payload['active_users'])?.[0]?.uid
    return {
      type: 'group.dismiss',
      ...base,
      ...(uid ? { operatorUid: uid, operators: [{ uid }] } : {}),
    }
  }
  return undefined
}

/** messageType=50011 群成员进出 diff（block_status 1=被移出/0=加入）；与 aweType 系统消息双通道并存 */
function groupMemberDiff (push: PushMessage): NoticeEvent | undefined {
  if (push.conversationType !== 2) return undefined
  const payload = commandPayload(push.content)
  const blockStatus = Number(payload?.['block_status'])
  if (blockStatus !== 0 && blockStatus !== 1) return undefined
  const members: NoticeUser[] = []
  // updated_participant_info 的 blocked 与 block_status 一致；缺标记时退回 userID
  for (const item of Array.isArray(payload?.['updated_participant_info']) ? payload?.['updated_participant_info'] : []) {
    const it = asRecord(item)
    if (!it || Number(it['blocked'] ?? -1) !== blockStatus) continue
    const uid = firstString(it, ['user_id', 'uid', 'userId'])
    if (!uid) continue
    const secUid = firstString(it, ['sec_uid', 'secUid'])
    members.push({ uid, ...(secUid ? { secUid } : {}) })
  }
  if (members.length === 0) {
    for (const uid of Array.isArray(payload?.['userID']) ? payload!['userID'] : []) {
      const text = uid == null ? '' : String(uid)
      if (text) members.push({ uid: text })
    }
  }
  if (members.length === 0) return undefined
  // 操作者即推送发送方（移出/加回由群主或管理员执行，仅有 uid）
  const operators: NoticeUser[] = push.senderUid ? [{ uid: push.senderUid }] : []
  const base = {
    conversationId: push.conversationId,
    conversationShortId: push.conversationShortId || push.conversationId,
    conversationType: 2 as const,
    members,
    operators,
    raw: push.raw,
  }
  return blockStatus === 1
    ? { type: 'group.member-decrease', ...base, source: 'kick' as const }
    : { type: 'group.member-increase', ...base, source: 'rejoin' as const }
}

/** messageType=50001 command_type=7 群成员增/删同步帧 → notice；
 * 加群/退群除 1001 aweType 系统消息、50011 diff 外还走这条同步通道（如退群常只发此帧），
 * 帧内无来源与操作者信息，source 记为 sync，操作者即推送发送方 */
export function groupMemberChangeFromCommand (push: PushMessage): NoticeEvent | undefined {
  if (push.conversationType !== 2) return undefined
  const payload = commandPayload(push.content)
  if (Number(payload?.['command_type']) !== 7) return undefined
  const added = uidList(payload?.['added_participant'])
  const removed = uidList(payload?.['removed_participant'])
  if (added.length === 0 && removed.length === 0) return undefined
  const base = {
    conversationId: push.conversationId,
    conversationShortId: push.conversationShortId || push.conversationId,
    conversationType: 2 as const,
    operators: push.senderUid ? [{ uid: push.senderUid }] : [],
    raw: push.raw,
  }
  // 罕见帧同时增删（多次操作合并）时优先透出剔除，加入侧由 status.memberChange 完整保留
  if (removed.length > 0) return { type: 'group.member-decrease', ...base, source: 'sync' as const, members: removed }
  return { type: 'group.member-increase', ...base, source: 'sync' as const, members: added }
}

/** 把 cmd500 中的协议命令消息与用户可见消息分流为 Notice 或 Request。 */
export function noticeFromPush (push: PushMessage): NoticeEvent | RequestEvent | undefined {
  const payload = commandPayload(push.content)
  const group = groupMemberIncrease(push, payload) ??
    groupMemberDecrease(push, payload) ??
    groupMeta(push, payload)
  if (group) return group
  if (!commandTypes.has(push.messageType)) return undefined
  if (push.messageType === 50011) {
    const diff = groupMemberDiff(push)
    if (diff) return diff
  }
  if (push.messageType === 40001) {
    // content 恒为 {}，被撤回消息与操作者信息全在 ext（s:target_server_message_id / s:recall_uid）
    const serverMessageId = push.ext?.['s:target_server_message_id']
    const targetClientMessageId = push.ext?.['s:target_client_message_id']
    const recallUid = push.ext?.['s:recall_uid']
    const recallRole = push.ext?.['s:recall_role']
    return {
      type: 'message.recall',
      conversationId: push.conversationId,
      conversationType: push.conversationType,
      ...(serverMessageId ? { serverMessageId } : {}),
      ...(targetClientMessageId ? { targetClientMessageId } : {}),
      ...(recallUid ? { recallUid } : {}),
      ...(recallRole ? { recallRole: Number(recallRole) } : {}),
      ...(push.ext ? { ext: push.ext } : {}),
      raw: push.raw,
    }
  }
  if (push.messageType === 50005) {
    // 会话删除（私聊删会话 / 群解散后清会话）；content 为空，标记只在 ext（:dissolv_his 表示解散）
    return {
      type: 'conversation.delete',
      conversationId: push.conversationId,
      conversationType: push.conversationType,
      ...(push.ext ? { ext: push.ext } : {}),
      raw: push.raw,
    }
  }
  if (push.messageType === 90001) {
    const apply = asRecord(payload?.['apply_info'] ?? payload?.['applyInfo'])
    const groupShortId = firstString(apply ?? payload, ['conv_short_id', 'convShortId', 'conversation_short_id', 'conversationShortId'])
    const requestId = firstString(apply ?? payload, ['apply_id', 'applyId', 'request_id', 'requestId'])
    return {
      type: 'group.join-request',
      conversationId: push.conversationId,
      conversationShortId: groupShortId || push.conversationShortId || push.conversationId,
      conversationType: push.conversationType,
      ...(requestId ? { requestId } : {}),
      content: push.content,
      raw: push.raw,
    }
  }
  return {
    type: 'im.command',
    conversationId: push.conversationId,
    conversationType: push.conversationType,
    messageType: push.messageType,
    content: push.content,
    raw: push.raw,
  }
}
