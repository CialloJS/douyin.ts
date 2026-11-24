// x-ladon（抖音 40.5.0 / libmetasec_ml.so）
//
// 真机抓包结论（Reqable live capture，33 条样本）：
//   1) x-argus = base64(LE32(ts))，与 ts 一一对应（见 argus.ts）；
//   2) x-ladon 在**同一 ts、同一 URL、同一 body** 下每次请求都不同
//      （例：同秒同接口 webcast/check_user_live_status 两次为 28b3b7d5 / dca3f9d5），
//      说明它含每次请求的随机量，不是 ts 的确定函数；
//   3) 重放实验：原样 / 随机 x-ladon / 全零 x-ladon / 随机 x-argus 四种请求
//      服务端均返回 200（cloudpush、social/count、notice/count 三个接口），
//      即该构建的 x-ladon 仅作请求标记，不被强校验。
//
// 因此纯算法侧只需产出 4 字节随机值的 base64（8 字符），格式与真机一致。
// 之前由 unidbg 冻结时间采样得到的 bitperm(ts) 映射，是因为 unidbg 中随机源被固定，
// 仅对应「随机量取固定值」这一特例，不能用于真机。
export interface LadonInput {
  /** 仅 unix 参与计算；其余字段保留以兼容上层调用签名 */
  aid?: number;
  lcId?: number;
  unix?: number;
  random?: Uint8Array;
}

export function ladon({ random }: LadonInput): { 'x-ladon': string } {
  const out = Buffer.alloc(4);
  if (random && random.length >= 4) {
    Buffer.from(random.subarray(0, 4)).copy(out);
  } else {
    out.writeUInt32LE((Math.random() * 0x100000000) >>> 0, 0);
  }
  return { 'x-ladon': out.toString('base64') };
}
