/**
 * App Frontier 帧编解码：结构对齐 com.bytedance.common.wschannel.model.Frame，
 * 与 web 的 pbbp2 不是同一套封装。64 位字段保持 bigint，回执要原样带回。
 */
import { fieldStringValue, fieldVarint, kv } from '../live/wire.js'

export interface Frame {
  seqid: bigint
  logid: bigint
  service: number
  method: number
  headers: Record<string, string>
  /** payload_encoding：__lz4 时需要先解压 */
  encoding: string
  payload: Buffer
  /** 服务端回执标识（字段 9），字符串形态 */
  logidnew: string
}

const text = new TextDecoder()

interface Cursor {
  pos: number
}

function varint (data: Uint8Array, c: Cursor): bigint {
  let value = 0n
  let shift = 0n
  while (c.pos < data.length) {
    const byte = data[c.pos++]!
    value |= BigInt(byte & 0x7f) << shift
    if ((byte & 0x80) === 0) return value
    shift += 7n
  }
  throw new Error('帧 varint 截断')
}

function chunk (data: Uint8Array, c: Cursor): Uint8Array {
  const len = Number(varint(data, c))
  const end = c.pos + len
  if (end > data.length) throw new Error('帧长度截断')
  const out = data.subarray(c.pos, end)
  c.pos = end
  return out
}

/** ExtendedEntry { 1: key, 2: value } */
function entry (data: Uint8Array): [string, string] | null {
  const c: Cursor = { pos: 0 }
  let key = ''
  let value = ''
  while (c.pos < data.length) {
    const tag = Number(varint(data, c))
    const raw = chunk(data, c)
    if (tag >>> 3 === 1) key = text.decode(raw)
    else if (tag >>> 3 === 2) value = text.decode(raw)
  }
  return key ? [key, value] : null
}

export function decodeFrame (data: Uint8Array): Frame | null {
  const frame: Frame = {
    seqid: 0n,
    logid: 0n,
    service: 0,
    method: 0,
    headers: {},
    encoding: '',
    payload: Buffer.alloc(0),
    logidnew: '',
  }
  const c: Cursor = { pos: 0 }
  try {
    while (c.pos < data.length) {
      const tag = Number(varint(data, c))
      const field = tag >>> 3
      const wire = tag & 7
      if (wire === 0) {
        const value = varint(data, c)
        if (field === 1) frame.seqid = value
        else if (field === 2) frame.logid = value
        else if (field === 3) frame.service = Number(value)
        else if (field === 4) frame.method = Number(value)
      } else if (wire === 2) {
        const raw = chunk(data, c)
        if (field === 5) {
          const item = entry(raw)
          if (item) frame.headers[item[0]] = item[1]
        } else if (field === 6) frame.encoding = text.decode(raw)
        else if (field === 8) frame.payload = Buffer.from(raw)
        else if (field === 9) frame.logidnew = text.decode(raw)
      } else if (wire === 1) c.pos += 8
      else if (wire === 5) c.pos += 4
      else return null
      if (c.pos > data.length) return null
    }
  } catch {
    return null
  }
  return frame
}

/** need_ack=1 的回执帧：复制序号与 service/method，只带 ack 头 */
export function ackFrame (frame: Frame): Buffer | null {
  if (frame.headers.need_ack !== '1') return null
  const headers = [
    kv(5, 'is_ack', '1'),
    kv(5, 'ack_id', frame.logidnew),
    kv(5, 'ack_code', '0'),
  ]
  const msgId = frame.headers.x_frontier_msgid
  if (msgId) headers.push(kv(5, 'x_frontier_msgid', msgId))
  return Buffer.concat([
    fieldVarint(1, frame.seqid),
    fieldVarint(2, frame.logid),
    fieldVarint(3, frame.service),
    fieldVarint(4, frame.method),
    ...headers,
    fieldStringValue(9, frame.logidnew),
  ])
}
