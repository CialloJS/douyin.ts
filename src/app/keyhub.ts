/** keyhub 握手：ECDH(P-256) + HKDF 派生 IM/API 两把 ChaCha20 会话密钥 */
import { createCipheriv, createECDH, createPrivateKey, hkdfSync, randomBytes, sign } from 'node:crypto'
import { request } from './http.js'
import { DEV, ua } from './conf.js'

const URL = 'https://keyhub.zijieapi.com/handshake'
const APP_ID = '1128'
/** 4097 = secp256r1 + HKDF-SHA256 + ChaCha20 */
const SUITE = 4097
/** info 是 16 字节 ASCII，不是 hex 解码后的 8 字节（运行时 hook 实证） */
const INFO_IM = Buffer.from('4e30514609050cd3', 'utf8')
const INFO_API = Buffer.from('cab4ac74f61b5835', 'utf8')

/** 提前 5 分钟续期，避免边界上拿到刚过期的 ticket */
export const MARGIN = 5 * 60 * 1000

export interface ImSession {
  /** base64(DER ticket)，即 x-tt-e-t */
  ticket: string
  ticketLong?: string
  /** IM 通道 key（32B） */
  keyIM: Buffer
  /** 普通 API 通道 key（32B） */
  keyAPI: Buffer
  issuedAt: number
  expiresAt: number
  deviceId: string
}

interface Resp {
  ticket?: string
  ticket_long?: string
  ticket_exp?: number
  random?: string
  key_share?: { pubkey?: string }
}

/** ChaCha20 (IETF)：加解密同一运算，iv = counter(4B) || nonce(12B) */
export function chacha20 (key: Buffer, nonce: Buffer, data: Buffer): Buffer {
  if (nonce.length !== 12) throw new Error(`ChaCha20 nonce 必须 12 字节，实际 ${nonce.length}`)
  const c = createCipheriv('chacha20', key, Buffer.concat([Buffer.alloc(4), nonce]))
  return Buffer.concat([c.update(data), c.final()])
}

/** 一次完整握手：生成 P-256 密钥对 → 签名 → POST → ECDH+HKDF */
export async function handshake (deviceId: string, timeoutMs = 20000): Promise<ImSession> {
  if (!deviceId) throw new Error('keyhub 握手缺少 device_id')
  const ecdh = createECDH('prime256v1')
  ecdh.generateKeys()
  const pub = ecdh.getPublicKey()
  const clientRandom = randomBytes(32)
  const payload = Buffer.from(
    JSON.stringify({
      app_id: APP_ID,
      cipher_suites: [SUITE],
      did: deviceId,
      key_shares: [{ curve: 'secp256r1', pubkey: pub.toString('base64') }],
      random: clientRandom.toString('base64'),
      version: 2,
    }),
    'utf8',
  )
  // x-tt-s-sign = base64(ECDSA-SHA256(priv, rawBody))
  const key = createPrivateKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: ecdh.getPrivateKey().toString('base64url'),
      x: pub.subarray(1, 33).toString('base64url'),
      y: pub.subarray(33, 65).toString('base64url'),
    },
  })
  const sig = sign('sha256', payload, key).toString('base64')
  const res = await request({
    url: URL,
    method: 'POST',
    headers: [
      ['content-type', 'application/json'],
      ['accept-encoding', 'gzip, deflate, br'],
      ['x-tt-request-tag', 'n=0;s=0;p=0;ns=0;ff=0;mp=0'],
      ['x-tt-s-sign', sig],
      ['user-agent', ua(DEV)],
    ],
    body: payload,
    timeoutMs,
  })
  if (res.status !== 200) throw new Error(`keyhub 握手失败 HTTP ${res.status}: ${res.text.slice(0, 200)}`)
  const j = res.json as Resp | undefined
  if (!j?.ticket || !j.key_share?.pubkey || !j.random) throw new Error(`keyhub 响应缺字段: ${res.text.slice(0, 200)}`)

  const shared = ecdh.computeSecret(Buffer.from(j.key_share.pubkey, 'base64'))
  const salt = Buffer.concat([clientRandom, Buffer.from(j.random, 'base64')])
  const now = Date.now()
  return {
    ticket: j.ticket,
    ticketLong: j.ticket_long,
    keyIM: Buffer.from(hkdfSync('sha256', shared, salt, INFO_IM, 32)),
    keyAPI: Buffer.from(hkdfSync('sha256', shared, salt, INFO_API, 32)),
    issuedAt: now,
    expiresAt: now + (j.ticket_exp && j.ticket_exp > 0 ? j.ticket_exp : 10800) * 1000,
    deviceId,
  }
}
