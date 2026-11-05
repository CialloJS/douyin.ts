/**
 * 无 schema 的 protobuf wire 编解码：用于诊断与未知 IM 推送。
 * 解码永不因截断抛错，只返回已完整解出的字段。
 */
import { cmd } from '../session/codes.js'

/** 无 schema 的 protobuf 字段：诊断与未知 IM 推送共用 */
export type WireField =
  | { field: number; type: 'varint'; value: bigint }
  | { field: number; type: 'fixed64'; value: Uint8Array }
  | { field: number; type: 'fixed32'; value: Uint8Array }
  | { field: number; type: 'string'; value: string }
  | { field: number; type: 'message'; value: WireField[] }
  | { field: number; type: 'bytes'; value: Uint8Array }

export interface WireTreeField {
  f: number
  t: WireField['type']
  v: string | WireTreeField[]
}

const MAX_DEPTH = cmd.depth
const textDecoder = new TextDecoder('utf-8', { fatal: true })

/** 定长 wire type 表：1=fixed64、5=fixed32（protobuf 其余定长类型不使用） */
const fixed: Record<number, { type: 'fixed64' | 'fixed32'; width: number } | undefined> = {
  1: { type: 'fixed64', width: 8 },
  5: { type: 'fixed32', width: 4 },
}

function decodeVarint (data: Uint8Array, start: number): { value: bigint; next: number } | null {
  let value = 0n
  let shift = 0n
  for (let pos = start; pos < data.length && shift < 70n; pos += 1, shift += 7n) {
    const byte = data[pos]!
    value |= BigInt(byte & 0x7f) << shift
    if ((byte & 0x80) === 0) return { value, next: pos + 1 }
  }
  return null
}

function safeText (data: Uint8Array): string | null {
  try {
    const text = textDecoder.decode(data)
    for (const ch of text) {
      const code = ch.codePointAt(0)!
      if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return null
    }
    return text
  } catch {
    return null
  }
}

export function decodeWire (data: Uint8Array, depth = 0): WireField[] {
  const fields: WireField[] = []
  let pos = 0
  while (pos < data.length) {
    const tag = decodeVarint(data, pos)
    if (!tag) break
    pos = tag.next
    const field = Number(tag.value >> 3n)
    const wireType = Number(tag.value & 7n)
    if (field === 0) break

    if (wireType === 0) {
      const item = decodeVarint(data, pos)
      if (!item) break
      pos = item.next
      fields.push({ field, type: 'varint', value: item.value })
      continue
    }

    const member = fixed[wireType]
    if (member) {
      if (pos + member.width > data.length) break
      const value = data.slice(pos, pos + member.width)
      pos += member.width
      fields.push({ field, type: member.type, value })
      continue
    }
    if (wireType !== 2) break

    const lengthItem = decodeVarint(data, pos)
    if (!lengthItem || lengthItem.value > BigInt(Number.MAX_SAFE_INTEGER)) break
    pos = lengthItem.next
    const length = Number(lengthItem.value)
    if (pos + length > data.length) break
    const raw = data.slice(pos, pos + length)
    pos += length

    const text = safeText(raw)
    const trimmed = text?.trimStart() ?? ''
    const knownText = trimmed.startsWith('{') || trimmed.startsWith('[') ||
      /^0:\d+:/.test(trimmed) || /^\d+$/.test(trimmed) || trimmed.startsWith('MS4') ||
      /^https?:\/\//.test(trimmed) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(trimmed)
    if (text != null && knownText) {
      fields.push({ field, type: 'string', value: text })
      continue
    }
    const nested = depth < MAX_DEPTH ? decodeWire(raw, depth + 1) : []
    if (nested.length > 0) fields.push({ field, type: 'message', value: nested })
    else if (text != null) fields.push({ field, type: 'string', value: text })
    else fields.push({ field, type: 'bytes', value: raw })
  }
  return fields
}

/** JSON 安全的诊断树：bigint 转十进制串，字节转 base64 */
export function decodeWireTree (data: Uint8Array): WireTreeField[] {
  const convert = (field: WireField): WireTreeField => {
    if (field.type === 'message') {
      return { f: field.field, t: field.type, v: field.value.map(convert) }
    }
    if (field.type === 'varint') {
      return { f: field.field, t: field.type, v: field.value.toString() }
    }
    if (field.type === 'string') return { f: field.field, t: field.type, v: field.value }
    return { f: field.field, t: field.type, v: Buffer.from(field.value).toString('base64') }
  }
  return decodeWire(data).map(convert)
}

export function encodeVarint (value: number | bigint): Buffer {
  let remaining = BigInt(value)
  const bytes: number[] = []
  do {
    let byte = Number(remaining & 0x7fn)
    remaining >>= 7n
    if (remaining) byte |= 0x80
    bytes.push(byte)
  } while (remaining)
  return Buffer.from(bytes)
}

export function fieldVarint (field: number, value: number | bigint): Buffer {
  return Buffer.concat([encodeVarint(field << 3), encodeVarint(value)])
}

export function fieldBytes (field: number, value: Uint8Array): Buffer {
  return Buffer.concat([encodeVarint(field << 3 | 2), encodeVarint(value.length), Buffer.from(value)])
}

export function fieldStringValue (field: number, value: string): Buffer {
  return fieldBytes(field, Buffer.from(value))
}

/** 嵌套 map<string,string> 键值项：field { 1: key, 2: value } */
export function kv (field: number, key: string, value: string): Buffer {
  return fieldBytes(field, Buffer.concat([fieldStringValue(1, key), fieldStringValue(2, value)]))
}
