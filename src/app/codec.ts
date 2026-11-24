/** 传输层编解码：zstd 压缩、按头/魔数解压、验证码 XOR */
import * as zlib from 'node:zlib'

const z = zlib as unknown as {
  zstdCompressSync?: (b: Uint8Array) => Buffer
  zstdDecompressSync?: (b: Uint8Array) => Buffer
}

export { md5Hex, ssStub } from './sign/hash.js'

/** x-bd-content-encoding: zstd */
export function zstdCompress (buf: Buffer): Buffer {
  if (!z.zstdCompressSync) throw new Error('当前 Node 不支持 zstd，需要 >= 22.15')
  return z.zstdCompressSync(buf)
}

export function hasZstd (b: Uint8Array): boolean {
  return b.length >= 4 && b[0] === 0x28 && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd
}

/** 按 content-encoding 或魔数解压（zstd / gzip / deflate / br） */
export function decompress (buf: Buffer, contentEncoding = ''): Buffer {
  const ce = contentEncoding.toLowerCase()
  if (hasZstd(buf)) return z.zstdDecompressSync!(buf)
  if (ce === 'zstd') return z.zstdDecompressSync!(buf)
  if (ce === 'br') return zlib.brotliDecompressSync(buf)
  if (ce === 'gzip' || ce === 'deflate') return zlib.gunzipSync(buf)
  return buf
}

/** WS 推送 payload_encoding=__lz4：帧内不带原始长度，按需扩容解 raw block */
export function lz4 (src: Uint8Array): Buffer {
  if (src.length === 0) return Buffer.alloc(0)
  let out = Buffer.alloc(Math.max(256, src.length * 3))
  let ip = 0
  let op = 0
  const ensure = (n: number): void => {
    if (op + n <= out.length) return
    const next = Buffer.alloc(Math.max(op + n, out.length * 2))
    out.copy(next, 0, 0, op)
    out = next
  }
  while (ip < src.length) {
    const token = src[ip++]!
    let len = token >>> 4
    if (len === 15) {
      let ext = 0
      do {
        if (ip >= src.length) throw new Error('lz4 数据截断')
        ext = src[ip++]!
        len += ext
      } while (ext === 255)
    }
    if (ip + len > src.length) throw new Error('lz4 字面量截断')
    ensure(len)
    out.set(src.subarray(ip, ip + len), op)
    ip += len
    op += len
    if (ip >= src.length) break
    if (ip + 2 > src.length) throw new Error('lz4 偏移截断')
    const offset = src[ip]! | (src[ip + 1]! << 8)
    ip += 2
    if (offset === 0 || offset > op) throw new Error('lz4 偏移越界')
    let match = token & 0x0f
    if (match === 15) {
      let ext = 0
      do {
        if (ip >= src.length) throw new Error('lz4 数据截断')
        ext = src[ip++]!
        match += ext
      } while (ext === 255)
    }
    match += 4
    ensure(match)
    let from = op - offset
    for (let i = 0; i < match; i++) out[op++] = out[from++]!
  }
  return out.subarray(0, op)
}

/** 真机行为：验证码先 XOR 0x05 再小写 hex */
export function xor5Hex (s: string): string {
  const b = Buffer.from(s, 'utf8')
  for (let i = 0; i < b.length; i++) b[i] ^= 0x05
  return b.toString('hex')
}
