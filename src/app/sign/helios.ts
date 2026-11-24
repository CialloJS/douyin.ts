// x-helios（抖音 40.5.0 / libmetasec_ml.so）
//
// 由 unidbg 动态插桩还原，并用真机 75 条样本逐字节验证：
// 给定真机前 4 字节 rand1，后 32 字节 75/75 完全复现。
//
//   x-helios = base64( LE32(rand1) ‖ tail32 )        // 36 字节 / 48 base64
//
//   rand1        ：so 内 srand 后的 rand() 输出（真机 75/75 均 < 2^31）
//   tail32       ：两趟 16 字节窗口各做 34 轮混合，每趟留下 (r4, r6) → 4×u64 小端
//
// 1) 随机数：bionic 的 rand() 就是 FreeBSD random()（TYPE_3：deg=31 / sep=3），
//    srand 播种后先丢弃 310 个输出，再返回 (state[f]+state[r]) >> 1。
// 2) 常量表：md5( LE32(rand1) ‖ String(aid) ) 的 32 字符小写 hex 直接当 32 字节，
//    切成 4 个 u64 作为种子，再递推 34 项：
//        t    = (ROR(s1, 8) + s0) ^ i
//        newA = t ^ ROL(s0, 3)
//        (s0,s1,s2,s3) <- (newA, s2, s3, t)
//    首项即 4 个 u64 里的 s0。
// 3) 输入串：`${ts}-${lid}-${aid}`（实测 26 字节，剩余 6 字节填充 0x06），
//    窗口 1 = buf[0..15]，窗口 2 = buf[16..31]。
// 4) 每轮：r6' = c ^ (ROR(r6, 8) + r4)，r4' = r6' ^ ROL(r4, 3)。
//
// lid 是 so 内部值（40.5.0 实测恒为 1588093228，与 device_id / iid 无关）。
// rand1 来自进程级 rand() 序列，真机上同一秒内每个请求都不同；本实现同样
// 维护进程级序列，因此无法（也不需要）与真机某个具体值逐字节相同。
import { createHash } from 'node:crypto';

const MASK64 = (1n << 64n) - 1n;

function ror64(x: bigint, n: number): bigint {
  const k = BigInt(n & 63);
  return ((x >> k) | (x << (64n - k))) & MASK64;
}

function rol64(x: bigint, n: number): bigint {
  const k = BigInt(n & 63);
  return ((x << k) | (x >> (64n - k))) & MASK64;
}

/** bionic rand()：FreeBSD random(TYPE_3)，播种后丢弃 310 个输出 */
function bionicRand(seed: number): () => number {
  let s = seed >>> 0;
  if (s === 0) s = 1;
  const st = new Uint32Array(31);
  st[0] = s;
  for (let i = 1; i < 31; i++) st[i] = (16807 * st[i - 1]) % 2147483647;
  let f = 3;
  let r = 0;
  const step = (): number => {
    const v = (st[f] + st[r]) >>> 0;
    st[f] = v;
    f = (f + 1) % 31;
    r = (r + 1) % 31;
    return (v >>> 1) & 0x7fffffff;
  };
  for (let i = 0; i < 310; i++) step();
  return step;
}

/** 常量表：md5(LE32(rand1) + aid) 的 hex 当 4×u64 种子，递推 34 项 */
function constantTable(rand1: number, aid: number): bigint[] {
  const head = Buffer.alloc(4);
  head.writeUInt32LE(rand1 >>> 0, 0);
  const hex = createHash('md5')
    .update(Buffer.concat([head, Buffer.from(String(aid))]))
    .digest('hex');
  const raw = Buffer.from(hex, 'latin1');
  let s0 = raw.readBigUInt64LE(0);
  let s1 = raw.readBigUInt64LE(8);
  let s2 = raw.readBigUInt64LE(16);
  let s3 = raw.readBigUInt64LE(24);
  const out: bigint[] = [s0];
  for (let i = 0; i < 33; i++) {
    const t = (((ror64(s1, 8) + s0) & MASK64) ^ BigInt(i)) & MASK64;
    const a = (t ^ rol64(s0, 3)) & MASK64;
    s0 = a;
    s1 = s2;
    s2 = s3;
    s3 = t;
    out.push(a);
  }
  return out;
}

function mix(r4: bigint, r6: bigint, consts: bigint[]): [bigint, bigint] {
  for (const c of consts) {
    const t = (c ^ ((ror64(r6, 8) + r4) & MASK64)) & MASK64;
    r4 = (t ^ rol64(r4, 3)) & MASK64;
    r6 = t;
  }
  return [r4, r6];
}

export interface HeliosInput {
  /** 与 X-Khronos 同一秒的 unix 时间戳 */
  unix?: number;
  /** so 内部 lid，默认 40.5.0 实测值 */
  lid?: number | string;
  aid?: number;
  /** 显式指定 srand 种子：每次调用都重新播种并取第一个 rand()（用于复现真机序列） */
  seed?: number;
  /** 直接指定 rand1（真机样本回放用） */
  rand1?: number;
}

/** 40.5.0 libmetasec_ml.so 内 lid 实测恒定，与设备 ID 无关 */
const DEFAULT_LID = 1588093228;

/** 进程级 rand() 序列：真机 srand 一次后每请求取下一个 */
let seq: (() => number) | null = null;

export function helios({
  unix,
  lid = DEFAULT_LID,
  aid = 1128,
  seed,
  rand1,
}: HeliosInput = {}): { 'x-helios': string } {
  const ts = unix ?? Math.floor(Date.now() / 1000);
  let r1: number;
  if (rand1 !== undefined) {
    r1 = rand1 >>> 0;
  } else if (seed !== undefined) {
    r1 = bionicRand(seed)();
  } else {
    if (!seq) seq = bionicRand(Math.floor(Date.now() / 1000));
    r1 = seq();
  }
  const consts = constantTable(r1, aid);

  // 32 字节窗口：字符串不足部分填 0x06（实测填充值）
  const buf = Buffer.alloc(32, 0x06);
  Buffer.from(`${ts}-${lid}-${aid}`, 'latin1').copy(buf, 0, 0, Math.min(32, buf.length));

  const w1 = mix(buf.readBigUInt64LE(0), buf.readBigUInt64LE(8), consts);
  const w2 = mix(buf.readBigUInt64LE(16), buf.readBigUInt64LE(24), consts);

  const out = Buffer.alloc(36);
  out.writeUInt32LE(r1 >>> 0, 0);
  [w1[0], w1[1], w2[0], w2[1]].forEach((v, i) => out.writeBigUInt64LE(v, 4 + i * 8));
  return { 'x-helios': out.toString('base64') };
}
