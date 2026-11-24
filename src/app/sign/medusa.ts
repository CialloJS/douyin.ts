import { randomBytes } from 'node:crypto';

/** x-medusa：外层结构可还原，载荷密文无法复现（服务端不校验内容，只校验结构） */
export interface MedusaInput {
  /** 与 x-khronos 同一秒的 unix */
  unix?: number;
  /** 参与签名的 query（不含前导 ?），只影响载荷长度 */
  query?: string;
  deviceId?: string;
  /** 2 字节随机量；不传则用 crypto 随机 */
  random?: Uint8Array;
}

/** so 内固定的 16 字节标识块（40.5.0，随版本变化） */
const MEDUSA_TAG = Buffer.from('ddc8bca0b9f6fe29cf365d46d2ee3f3c', 'hex');

/** FNV-1a 32 位，用作伪随机流的种子 */
function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

export function medusa(input: MedusaInput = {}): { 'x-medusa': string } {
  const ts = (input.unix ?? Math.floor(Date.now() / 1000)) >>> 0;
  const query = input.query ?? '';

  const head = Buffer.alloc(24);
  head.writeUInt32LE(ts, 0);
  MEDUSA_TAG.copy(head, 4);
  const rnd =
    input.random && input.random.length >= 2 ? Buffer.from(input.random.subarray(0, 2)) : randomBytes(2);
  rnd.copy(head, 20);
  head.writeUInt16BE(0x0001, 22);

  // 载荷：同 ts + query 下保持稳定，避免每次请求都抖动
  const bodyLen = 812 + Math.min(4, Math.floor(query.length / 64));
  const body = Buffer.alloc(bodyLen);
  let s = fnv1a(`${ts}|${query}|${input.deviceId ?? ''}`);
  for (let i = 0; i < bodyLen; i++) {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    body[i] = s & 0xff;
  }

  return { 'x-medusa': Buffer.concat([head, body]).toString('base64') };
}
