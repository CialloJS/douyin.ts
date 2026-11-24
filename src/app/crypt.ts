/** passport 请求体加密信封（native ttEncrypt）：74 63 05 10 + 32B keyStream + AES-128-CBC 密文 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'

const HEAD = Buffer.from([0x74, 0x63, 0x05, 0x10, 0, 0])

const ORD = Buffer.from(
  '4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58',
  'hex',
)

/** AES key = SHA512(SHA512(keyStream) + ORD)[0:16]，IV = 同结果 [16:32] */
function derive (keyStream: Buffer): { key: Buffer; iv: Buffer } {
  const s = createHash('sha512').update(keyStream).digest()
  const d = createHash('sha512').update(Buffer.concat([s, ORD])).digest()
  return { key: d.subarray(0, 16), iv: d.subarray(16, 32) }
}

export function ttEncrypt (payload: string | Buffer): Buffer {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8')
  const keyStream = randomBytes(32)
  const { key, iv } = derive(keyStream)
  const c = createCipheriv('aes-128-cbc', key, iv)
  const digest = createHash('sha512').update(body).digest()
  const ct = Buffer.concat([c.update(Buffer.concat([digest, body])), c.final()])
  return Buffer.concat([HEAD, keyStream, ct])
}

/** 返回去掉 SHA512 摘要后的明文 */
export function ttDecrypt (blob: Buffer): Buffer {
  if (blob.subarray(0, 4).toString('hex') !== '74630510') throw new Error('not ttEncrypt blob')
  const { key, iv } = derive(blob.subarray(6, 38))
  const d = createDecipheriv('aes-128-cbc', key, iv)
  const pt = Buffer.concat([d.update(blob.subarray(38)), d.final()])
  return pt.subarray(64)
}
