/** ee.info 通道：96B key 包 (A16 || M48 || B32) 的密封/解封，与 keyhub HKDF 是两条独立链路 */
import { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto'
import type { ImSession } from './keyhub.js'

const SEED = pbkdf2Sync('TokenManager', '0x801020', 1001, 16, 'sha1')
export const EE_KA = pbkdf2Sync('ee.info', SEED, 1003, 16, 'sha1')
export const EE_KH = pbkdf2Sync('ee.info', SEED, 1004, 16, 'sha1')

export interface EeEntry {
  id: string
  type?: number
  /** 96B key 包 base64 */
  key: string
  /** x-tt-e-t */
  ticket?: string
  /** 秒 */
  expire?: number
  r_exp?: number
}

export interface EeKey {
  A: Buffer
  M: Buffer
  B: Buffer
  /** B == HMAC-SHA256(K_h, A||M) */
  valid: boolean
  /** ChaCha20 会话密钥（32B） */
  chachaKey: Buffer
}

/** 解开 96B key 包：key = AES-128-CBC(K_a, IV=A).decrypt(M)[:32] */
export function parseEeKey (b64: string): EeKey {
  const blob = Buffer.from(b64, 'base64')
  if (blob.length !== 96) throw new Error(`ee.info key 应为 96B，实际 ${blob.length}B`)
  const A = blob.subarray(0, 16)
  const M = blob.subarray(16, 64)
  const B = blob.subarray(64, 96)
  const valid = createHmac('sha256', EE_KH).update(Buffer.concat([A, M])).digest().equals(B)
  const d = createDecipheriv('aes-128-cbc', EE_KA, A)
  d.setAutoPadding(false)
  const plain = Buffer.concat([d.update(M), d.final()])
  return { A, M, B, valid, chachaKey: plain.subarray(0, 32) }
}

/** 把已配对的 32B key 封成 96B 包；凭空造 key 服务端会拒 */
export function packEeKey (chachaKey: Buffer, A: Buffer = randomBytes(16)): string {
  if (chachaKey.length !== 32) throw new Error(`chachaKey 应为 32B，实际 ${chachaKey.length}B`)
  if (A.length !== 16) throw new Error(`A 应为 16B，实际 ${A.length}B`)
  const c = createCipheriv('aes-128-cbc', EE_KA, A)
  const M = Buffer.concat([c.update(chachaKey), c.final()])
  const B = createHmac('sha256', EE_KH).update(Buffer.concat([A, M])).digest()
  return Buffer.concat([A, M, B]).toString('base64')
}

/** keyhub 会话 → ee.info 条目（id 形如 `<uid>+IM`） */
export function eeEntry (sess: ImSession, id: string): EeEntry {
  return { id, type: 1, key: packEeKey(sess.keyIM), ticket: sess.ticket, expire: sess.expiresAt / 1000 }
}

/** ee.info 条目 → IM 会话（ticket 用缓存值，key 走 96B 包派生） */
export function eeSession (e: EeEntry, deviceId = ''): ImSession {
  if (!e.ticket) throw new Error(`ee.info 条目 ${e.id} 缺 ticket`)
  const { chachaKey } = parseEeKey(e.key)
  const expiresAt = e.expire ? e.expire * 1000 : Date.now() + 3600_000
  return {
    ticket: e.ticket,
    keyIM: chachaKey,
    keyAPI: chachaKey,
    issuedAt: e.r_exp ? expiresAt - e.r_exp * 1000 : 0,
    expiresAt,
    deviceId,
  }
}
