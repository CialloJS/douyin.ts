// x-argus（抖音 40.5.0 / libmetasec_ml.so）
//
// 该构建在完整 init + frameSign 路径下产出的 X-Argus 就是 4 字节的时间戳（小端）base64：
//   ts=0x6AF3AB00 -> 00 ab f3 6a -> "AKvzag=="
// 已用 unidbg 冻结时间逐点验证，与 url / cookie / device 无关。
export interface ArgusInput {
  /** 仅 unix 参与计算；其余字段保留以兼容上层调用签名 */
  query?: string;
  body?: string | Uint8Array | null;
  unix?: number;
  aid?: number;
  lcId?: number;
  deviceId?: string;
  sdkVer?: string;
  sdkVerCode?: number;
  versionName?: string;
  rand?: number;
}

export function argus({ unix }: ArgusInput): { 'x-argus': string } {
  const ts = (unix ?? Math.floor(Date.now() / 1000)) >>> 0;
  const out = Buffer.alloc(4);
  out.writeUInt32LE(ts, 0);
  return { 'x-argus': out.toString('base64') };
}
