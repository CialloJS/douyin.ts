import { encodeVarint, type WireField } from '../live/wire.js'
import type { NoticeUser } from '../types.js'

/** 无 schema wire 辅助（等价 android-ws.ts 的提取 helpers，通知与推送共用） */

export function fieldString (fields: WireField[], number: number): string | undefined {
  for (const field of fields) {
    if (field.field === number && field.type === 'varint') return field.value.toString()
    if (field.field === number && field.type === 'string') return field.value
  }
  return undefined
}

export function messageChildren (fields: WireField[], number: number): WireField[][] {
  return fields
    .filter((field): field is Extract<WireField, { type: 'message' }> =>
      field.field === number && field.type === 'message',
    )
    .map((field) => field.value)
}

/** 还原客户端 fixed64 打包的短键：f1 嵌套 message 的子字段字节顺序拼成 ASCII（如 :group_co 补全） */
function keyFromNested (fields: WireField[], number: number): string | undefined {
  const nested = fields.find(
    (field): field is Extract<WireField, { type: 'message' }> =>
      field.field === number && field.type === 'message',
  )?.value
  if (!nested?.length) return undefined
  const parts: Buffer[] = []
  for (const field of nested) {
    if (field.type === 'fixed64' || field.type === 'fixed32') parts.push(Buffer.from(field.value))
    else if (field.type === 'varint') parts.push(encodeVarint(field.value))
  }
  const text = Buffer.concat(parts).toString('utf8')
  return text || undefined
}

export function collectKeyValues (fields: WireField[], number: number): Map<string, string> {
  const values = new Map<string, string>()
  for (const child of messageChildren(fields, number)) {
    // 短键（≤8 ASCII 字符，如 :group_comment 拆分打包）客户端按 fixed64/fixed32 字面量打包，f1 非 string，需还原成键
    const key = fieldString(child, 1) ?? keyFromNested(child, 1)
    const value = fieldString(child, 2)
    if (key && value != null) values.set(key, value)
  }
  return values
}

/** 16+ 位整数（uid/conversation_id）超出 Number 精度，包成字符串再 parse；
 * 覆盖对象键值、数组元素与首元素，字符串内的数字（已带引号）不重复包装 */
export function protectBigInt (text: string): string {
  return text.replace(/(?<![\d"])(\d{16,})(?![\d"])/g, '"$1"')
}

export function asRecord (value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null
    ? value as Record<string, unknown>
    : undefined
}

export function firstString (record: Record<string, unknown> | undefined, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record?.[key]
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint') {
      const text = String(value)
      if (text && text !== '0') return text
    }
  }
  return undefined
}

/** 命令帧 content 解析：非法或非对象一律 undefined，由调用方按缺省处理 */
export function commandPayload (content: string): Record<string, unknown> | undefined {
  try {
    return asRecord(JSON.parse(protectBigInt(content)))
  } catch {
    return undefined
  }
}

export function noticeUsers (value: unknown): NoticeUser[] {
  if (!Array.isArray(value)) return []
  const users: NoticeUser[] = []
  for (const item of value) {
    const user = asRecord(item)
    const uid = firstString(user, ['uid', 'user_id', 'userId'])
    if (!uid) continue
    const secUid = firstString(user, ['sec_uid', 'secUid', 'sec_user_id', 'secUserId'])
    const nickname = firstString(user, ['nickname', 'nick_name', 'display_name', 'displayName'])
    users.push({
      uid,
      ...(secUid ? { secUid } : {}),
      ...(nickname ? { nickname } : {}),
    })
  }
  return users
}

/** 裸 uid 数组（added_participant 等） */
export function uidList (value: unknown): NoticeUser[] {
  if (!Array.isArray(value)) return []
  const users: NoticeUser[] = []
  for (const item of value) {
    const text = item == null ? '' : String(item)
    if (text) users.push({ uid: text })
  }
  return users
}
