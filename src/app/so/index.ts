/** x-medusa 真机同源签名：设备注册/激活必须解释执行 libmetasec_ml.so，纯算会被风控判 device_id=0 */
import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SoSigner } from './signer.js'

/** 源码运行与打包运行的位置不同，按候选目录找内置资产 */
const here = dirname(fileURLToPath(import.meta.url))
const root = [
  resolve(here, '../../../assets'),
  resolve(here, '../assets'),
  resolve(process.cwd(), 'assets'),
].find(dir => existsSync(join(dir, 'libmetasec_ml.so')))

export interface SoIds {
  deviceId?: string
  installId?: string
}

const soPath = root ? join(root, 'libmetasec_ml.so') : ''
const libDir = root ? join(root, 'lib64') : ''
/** 同一设备身份复用已预热的实例：冷启动约 1s，预热后每次签名约 0.25s */
const pool = new Map<string, SoSigner>()

function signerOf (ids: SoIds, ts: number): SoSigner {
  if (!soPath) throw new Error('找不到 assets/libmetasec_ml.so')
  const key = `${ids.deviceId ?? ''}|${ids.installId ?? ''}`
  const cached = pool.get(key)
  if (cached) return cached
  const signer = new SoSigner({
    cold: { soPath, libDir, deviceId: ids.deviceId ?? '', installId: ids.installId ?? '' },
    url: '',
    ts,
  })
  signer.warmUp()
  pool.set(key, signer)
  return signer
}

/** 生成六神签名头（小写键）；ids 为空表示注册前/匿名会话尚无设备身份 */
export function soSign (url: string, body?: Uint8Array, ids: SoIds = {}): Record<string, string> {
  // 签名时间必须与 URL 里的时间戳一致，跨秒会被服务端判重放；
  // captcha 只带 tmp(ms)，没有 ts，要按同一个时刻换算而不是另取当前秒
  const q = new URL(url).searchParams
  const ts = Number(q.get('ts')) || Math.floor((Number(q.get('tmp')) || Date.now()) / 1000)
  const headers = signerOf(ids, ts).signFast(url, body ? { bytes: body } : undefined, ts).headers
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
}
