// x-gorgon 8404 —— 按真机 libmetasec_ml.so 40.5.0 的 0x2dbad4 逐指令复刻
// （真机 7/7 样本 + 历史 HAR 151/151 逐字节验证通过）
//
// 明文 20 字节：md5(query)[0..3] | x-ss-stub[0..3] | 0*4 | 00040a04 | khronos[0..3](大端)
// 注意：query 是「签名 query」——当请求把公共参数放进 x-common-params-v2 头时，
// 签名串 = URL 上的 query 原样拼接该头（query 末尾的 & 保留），否则就是 URL query 本身。
// 密钥 8 字节：key = [0x4a, arg1_lo, 0x16, key3, 0x47, 0x6c, arg1_hi, key7]
//   arg1_lo/arg1_hi 真机 52/52 样本恒为 0x04/0x04，即 ARG1 = 0x0404；
//   key3/key7 在真机上取自输出缓冲区堆指针的第 1/2 字节（每请求不同），
//   服务端只能从 x-gorgon 前缀 [0x84,0x04,key7,key3,arg1_lo,arg1_hi] 反查，故客户端可任取；
//   key7 真机恒为 32 字节对齐（低字节 ∈ {0,0x20,...,0xe0}）。
// 头部 6 字节：84 04 key7 key3 arg1_lo arg1_hi
//
// 已用真机 40.5.0 抓包逐字节验证：给定真机 head 中的 key3/key7 与 x-ss-stub，
// 20 字节输出可 100% 复现（3/3 FULL MATCH）。
import { md5Hex } from './hash.js';

const LENGTH = 20;
const ARG1 = 0x0404;

// 覆盖式 KSA（真机 0x2dbcb4..0x2dbd30：t[i] = t[j]，不做交换）
function table(key: number[]): number[] {
  const t = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + t[i] + key[i & 7]) & 0xff;
    t[i] = t[j];
  }
  return t;
}

// 就地 PRGA（真机 0x2dbd34..0x2dbdd0）：
// a=(a+1)&0xff; j=(j+t[a])&0xff; D=t[j]; t[a]=D; t[j]=D; out[i]^=t[(D+D)&0xff]
function initialize(input: number[], hexZu: number[]): number[] {
  const t = hexZu.slice();
  let a = 0;
  let j = 0;
  for (let i = 0; i < input.length; i++) {
    a = (a + 1) & 0xff;
    j = (j + t[a]) & 0xff;
    const D = t[j];
    t[a] = D;
    t[j] = D;
    input[i] ^= t[(D + D) & 0xff];
  }
  return input;
}

function reverse(num: number): number {
  return ((num >> 4) | (num << 4)) & 0xff;
}

function rbit(num: number): number {
  let out = 0;
  for (let i = 0; i < 8; i++) out |= ((num >> i) & 1) << (7 - i);
  return out;
}

// 尾处理（真机 0x2dbddc..0x2dbec0）：就地覆盖，末字节环绕引用的是已处理的 input[0]
function handle(input: number[]): number[] {
  for (let i = 0; i < LENGTH; i++) {
    const B = reverse(input[i]);
    const C = input[(i + 1) % LENGTH];
    input[i] = ~(rbit(B ^ C) ^ LENGTH) & 0xff;
  }
  return input;
}

function hex2(num: number): string {
  return num.toString(16).padStart(2, '0');
}

export interface GorgonInput {
  /** URL 上的原始 query（不含前导 ?） */
  query: string;
  /** 若公共参数被放到 x-common-params-v2 头，则把该头的值传进来 */
  commonParams?: string;
  stub?: string;
  unix?: number;
  /** 真机 head 中的 key3/key7；不传则随机生成（格式与真机一致） */
  key3?: number;
  key7?: number;
}

export function gorgon({ query, commonParams, stub, unix, key3, key7 }: GorgonInput): {
  'x-gorgon': string;
  'x-khronos': string;
} {
  // 真机签名串 = URL query 原样 + x-common-params-v2（query 非空且未以 & 结尾时补一个 &）
  const signedQuery = commonParams
    ? query + (query && !query.endsWith('&') ? '&' : '') + commonParams
    : query;
  const ts = unix ?? Math.floor(Date.now() / 1000);
  const k3 = (key3 ?? Math.floor(Math.random() * 256)) & 0xff;
  const k7 = (key7 ?? (Math.floor(Math.random() * 8) << 5)) & 0xff;
  const key = [0x4a, ARG1 & 0xff, 0x16, k3, 0x47, 0x6c, (ARG1 >> 8) & 0xff, k7];
  const bytes: number[] = [];
  const pushHex = (hex: string, n = 4) => {
    for (let i = 0; i < n; i++) bytes.push(parseInt(hex.slice(2 * i, 2 * i + 2), 16));
  };
  pushHex(md5Hex(signedQuery));
  if (stub) pushHex(stub.slice(0, 8));
  else bytes.push(0, 0, 0, 0);
  // 真机此处恒为 0（并不掺 cookie），历史 151 条 HAR 全部复现
  bytes.push(0, 0, 0, 0);
  // 40.5.0 libmetasec_ml.so 内硬编码的 4 字节版本标记
  bytes.push(0x00, 0x04, 0x0a, 0x04);
  pushHex((ts & 0xffffffff).toString(16).padStart(8, '0'));
  if (bytes.length !== LENGTH) throw new Error(`gorgon input length ${bytes.length}`);

  const out = handle(initialize(bytes, table(key)))
    .map(hex2)
    .join('');
  const head = `8404${hex2(key[7])}${hex2(key[3])}${hex2(key[1])}${hex2(key[6])}`;
  return {
    'x-gorgon': head + out,
    'x-khronos': String(ts),
  };
}
