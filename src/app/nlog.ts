/** a0_ 设备证明：解释执行 libnative_log.so，生成 NativeLogManager 的 MMapResult */
import { existsSync } from 'node:fs'
import { uptime } from 'node:process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SoSigner } from './so/signer.js'

const here = dirname(fileURLToPath(import.meta.url))

/** 源码运行与打包运行的位置不同，按候选目录找内置资产 */
function assetDir (name: string): string {
  const dir = [
    resolve(here, '../../assets'),
    resolve(here, '../assets'),
    resolve(process.cwd(), 'assets'),
  ].find(d => existsSync(join(d, name)))
  if (!dir) throw new Error(`找不到 assets/${name}`)
  return dir
}

/** Java_ 静态注册的导出名，直接按 ELF 符号调用 */
const EXPORT = 'Java_com_ss_android_deviceregister_nativeManager_NativeLogManager_getMMMapResult'

/** 因子默认值：服务端未下发采集配置时只能填空画像，index 沿用真机配置 */
const FACTORS: Array<[string, number, () => string]> = [
  ['d_i0', 1, () => '{}'],
  ['d_a0', 1, () => '{}'],
  ['d_r0', 1, () => 'abc'],
  ['d_b0', 2, () => String(Math.round(Date.now() - uptime() * 1000))],
  ['d_m0', 1, () => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
]

class Nlog {
  private readonly so: SoSigner

  constructor (deviceId: string) {
    const dir = assetDir('libnative_log.so')
    this.so = new SoSigner({
      cold: { soPath: join(dir, 'libnative_log.so'), libDir: join(dir, 'lib64'), deviceId, installId: '' },
      url: '',
      ts: 0,
    })
    this.so.coldStart()
  }

  /** 返回紧凑二进制 MMapResult，后续与「_秒」一起做 RSA 加密 */
  mmap (version: number, tag: string): Uint8Array {
    const pairs = FACTORS.map(([k, index, value]) => [
      this.so.makeHandle({ kind: 'string', val: k }),
      this.so.makeHandle({ kind: 'json', val: { index, value: value() } }),
    ])
    const map = this.so.makeHandle({ kind: 'map', val: pairs })
    const s = this.so.makeHandle({ kind: 'string', val: tag })
    const h = this.so.coldExport(EXPORT, [this.so.coldEnvAddr, this.so.coldClassAddr, map, version, 0, s])
    const o = this.so.readHandle(h)
    if (!o || o.kind !== 'bytearray') throw new Error('native_log 未返回 MMapResult')
    return o.val as Uint8Array
  }
}

/** 冷启动解释器代价高，同一设备进程内复用 */
const pool = new Map<string, Nlog>()

export function mmap (deviceId: string, version: number, tag: string): Uint8Array {
  let n = pool.get(deviceId)
  if (!n) {
    n = new Nlog(deviceId)
    pool.set(deviceId, n)
  }
  return n.mmap(version, tag)
}
