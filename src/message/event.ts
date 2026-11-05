import { decodeWire, type WireField } from '../live/wire.js'
import { num, parseContent, str } from './json.js'
import type {
  GroupMemberChange,
  GroupMemberUpdate,
  NoticeEvent,
  PushMessage,
  ReadEvent,
  StatusEvent,
  StatusExtItem,
  VoipCallEvent,
} from '../types.js'

/** messageType=50018 来电推送 → voip 事件；content 无 call_info（异常/非来电变体）返回 undefined */
export function toVoipCall (push: PushMessage): VoipCallEvent | undefined {
  const parsed = parseContent(push.content)
  if (!parsed) return undefined
  const call = parsed.call_info as Record<string, unknown> | undefined
  if (!call) return undefined
  return {
    type: 'voip.call',
    conversationId: push.conversationId,
    conversationType: push.conversationType,
    callerUid: push.senderUid,
    callId: str(call.call_id),
    roomId: str(call.room_id),
    voipType: num(call.voip_type),
    callType: num(call.call_type),
    cameraOff: num(call.camera_off),
    callInfo: call,
  }
}

/** messageType=50013 单聊已读回执 → read 事件；content 无 P2PSender（异常变体）返回 undefined */
export function toReadEvent (push: PushMessage): ReadEvent | undefined {
  const info = parseContent(push.content)
  if (!info) return undefined
  const readerUid = info.P2PSender
  if (readerUid == null) return undefined
  return {
    type: 'read',
    conversationId: push.conversationId,
    readerUid: str(readerUid),
    conShortId: str(info.ConShortId),
    messageId: str(info.MessageId),
    readIndex: str(info.P2PSenderReadIndex),
  }
}

/** messageType=50001 会话状态变更 → status 事件；content 无 conversation_id（异常变体）返回 undefined */
export function toStatusEvent (push: PushMessage): StatusEvent | undefined {
  // protectBigInt：群成员/群主 uid 为 16+ 位，默认 JSON.parse 丢精度（raw 内数字均带引号保真）
  const info = parseContent(push.content, true)
  if (!info) return undefined
  const conversationId = info.conversation_id
  if (conversationId == null) return undefined
  const extData = Array.isArray(info.ext_data) ? statusExt(info.ext_data) : undefined
  const memberDiff = num(info.command_type) === 7 ? memberChange(info) : undefined
  return {
    type: 'status',
    conversationId: str(conversationId),
    conversationType: num(info.conversation_type),
    commandType: num(info.command_type),
    ...(info.read_badge_count != null ? { unread: num(info.read_badge_count) } : {}),
    readIndex: str(info.read_index),
    ...(push.serverMessageId ? { messageId: push.serverMessageId } : {}),
    // command_type=6 会话属性变更帧：按 ext_data 键判定群名/群头像变更，取本帧全量下发的新值；=7 群成员变更帧：按增删/角色/群主/群昵称变更解析
    ...(num(info.command_type) === 6 ? convChange(info, extData) : {}),
    ...(memberDiff ? { memberChange: memberDiff } : {}),
    ...(extData ? { extData } : {}),
    raw: info,
  }
}

/** command_type=6 帧 → 群名/群头像变更；改名帧也带头像键，按 ext_data 变更键优先定夺，故改名判定在头像之前 */
function convChange (info: Record<string, unknown>, extData?: StatusExtItem[]): Partial<StatusEvent> {
  const hit = (key: string): StatusExtItem | undefined => extData?.find(item => item.key === key)
  // 改名：a:s_name_operator 值记操作者；a:group_name_lifecycle 须为 name_change（建群/头像帧也带 lifecycle 但 event=group_create）
  const nameOp = hit('a:s_name_operator')
  const lifecycle = hit('a:group_name_lifecycle')
  if (nameOp || (lifecycle && lifecycle.value.includes('name_change'))) {
    return { nameChange: { name: str(info.conversation_name), operatorUid: nameOp ? nameOp.value : '' } }
  }
  // 改头像：a:group_avatar_user_set / s_user_set_avatar 值记操作者；a:ab_avatar 值即新头像（无签名），conversation_icon 带签名为准
  const avatarOp = hit('a:group_avatar_user_set') ?? hit('s_user_set_avatar')
  const avatarUrl = hit('a:ab_avatar')
  if (avatarOp || avatarUrl) {
    return { avatarChange: { icon: str(info.conversation_icon) || (avatarUrl ? avatarUrl.value : ''), operatorUid: avatarOp ? avatarOp.value : '' } }
  }
  return {}
}

/** command_type=7 帧 → 群成员变更（增删成员/角色/群主/群昵称变更）；无任何变化返回 undefined */
function memberChange (info: Record<string, unknown>): GroupMemberChange | undefined {
  const updated = (Array.isArray(info.updated_participant_info) ? info.updated_participant_info : [])
    .map((item): GroupMemberUpdate => {
      const it = item as Record<string, unknown>
      return {
        uid: str(it.user_id),
        role: num(it.role),
        ...(it.sec_uid ? { secUid: str(it.sec_uid) } : {}),
        // alias 下发即变更（含空串=昵称被清空），未下发才是「未涉及昵称」，故不做真值判断
        ...(typeof it.alias === 'string' ? { alias: it.alias } : {}),
      }
    })
    .filter(u => u.uid !== '')
  const added = stringArray(info.added_participant)
  const removed = stringArray(info.removed_participant)
  if (added.length === 0 && removed.length === 0 && updated.length === 0) return undefined
  // 群主变更只有 new_owner_id 非 0 才算：普通帧的 old_owner_id 是现任群主（恒有值），
  // 单看它会误判成「群主移交」，故 old/new 必须成对透出
  const oldOwnerId = str(info.old_owner_id)
  const newOwnerId = str(info.new_owner_id)
  const transfer = newOwnerId !== '' && newOwnerId !== '0'
  return {
    added,
    removed,
    updated,
    ...(transfer && oldOwnerId !== '' && oldOwnerId !== '0' ? { oldOwnerId } : {}),
    ...(transfer ? { newOwnerId } : {}),
  }
}

function stringArray (value: unknown): string[] {
  return Array.isArray(value)
    ? value.map(v => (v == null ? '' : String(v))).filter(v => v !== '')
    : []
}

/** content.ext_data → 会话属性变更项（key/value/version/op_type） */
function statusExt (items: unknown[]): StatusExtItem[] {
  return items.map((item) => {
    const it = item as Record<string, unknown>
    return {
      key: str(it.key),
      value: str(it.value),
      version: num(it.version),
      opType: num(it.op_type),
    }
  })
}

/** varint 字段值（bigint → string） */
function fieldVarint (fields: WireField[], field: number): string | undefined {
  const hit = fields.find(item => item.type === 'varint' && item.field === field)?.value as bigint | undefined
  return hit?.toString()
}

/**
 * cmd=500 field=500 property 推送 → 消息表情回应（ModifyPropertyBody 同构下发）：
 * f1=conversation_id, f2=conversation_type, f3=conversation_short_id, f4=server_message_id,
 * f5=client_message_id, f6=repeated ModifyPropertyContent{operation=1,key=2,value=3,idempotent_id=4}
 */
export function extractReactions (payload: Uint8Array): NoticeEvent[] {
  const events: NoticeEvent[] = []
  const visit = (fields: WireField[]): void => {
    for (const item of fields) {
      if (item.type === 'message') visit(item.value)
      if (item.type !== 'message' || item.field !== 500) continue
      for (const body of item.value.filter(inner => inner.type === 'message' && inner.field === 5)) {
        const list = body.value as Extract<WireField, { type: 'message' }>['value']
        const conversationId = list.find(inner => inner.type === 'string' && inner.field === 1)?.value as string | undefined
        // serverMessageId 为 19 位 int64；短于 18 位的是 shortId 之类字段
        const bigId = (field: number): string | undefined => {
          const value = fieldVarint(list, field)
          return value && value.length >= 18 ? value : undefined
        }
        const serverMessageId = bigId(4) ?? bigId(3)
        if (!conversationId || !serverMessageId) continue
        for (const content of list.filter(inner => inner.type === 'message' && inner.field === 6)) {
          const inner = (content as Extract<WireField, { type: 'message' }>).value as WireField[]
          const operation = Number(fieldVarint(inner, 1) ?? '0')
          const rawKey = inner.find(el => el.type === 'string' && el.field === 2)?.value as string | undefined
          const operatorUid = inner.find(el => el.type === 'string' && el.field === 4)?.value as string | undefined
          // 表态 key 形如 se:[爱心]；容忍其他前缀
          if (!rawKey || !rawKey.includes(':')) continue
          events.push({
            type: 'message.reaction',
            conversationId,
            serverMessageId,
            emoji: rawKey.replace(/^se:/, ''),
            operatorUid: operatorUid ?? '',
            isSet: operation === 0,
            raw: {},
          })
        }
      }
    }
  }
  visit(decodeWire(payload))
  return events
}
