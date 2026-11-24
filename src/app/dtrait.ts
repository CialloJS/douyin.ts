/** 设备证明与场景报告：x-tt-device-dtrait 走 native_log 的 a0_，x-bb-* 走 badger */
import { constants, createPublicKey, publicEncrypt } from 'node:crypto'
import { join } from 'node:path'
import { assetDir } from '../asset.js'
import { SoSigner } from './so/signer.js'
import { mmap } from './nlog.js'
import type { Ids } from './types.js'

/** 登录场景号（BadgerDtraitReporter 里 passport 走的 scene） */
const SCENE = 17

export interface Dtrait {
  /** x-tt-device-dtrait：<pk1_version>_Base64(RSA(mmap_秒)) */
  payload: string
  /** x-tt-device-signal / x-bb-signal：毫秒，必须与同批证据一致 */
  signal: string
  /** x-bb-data：badger 场景报告（无前缀） */
  data: string
  /** x-bb-scene */
  scene: string
}

type Val = number | bigint | string | Uint8Array

interface Node {
  t: number
  v?: Val
}

const be = (n: number): number[] => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]

const int = (v: number): number[] => [1, ...be(v)]

const str = (v: string): number[] => {
  const b = Buffer.from(v, 'utf8')
  return [3, (b.length >> 8) & 255, b.length & 255, ...b]
}

const bytes = (b: Uint8Array): number[] => [4, (b.length >> 8) & 255, b.length & 255, ...b]

/** murmur2：Java 侧用它对 deviceId 取 hash 拼挑战原文，换算法挑战值就对不上 */
function m2 (data: Buffer): number {
  const len = data.length
  const n = len >> 2
  let h = 0
  for (let i = 0; i < n; i++) {
    const o = i << 2
    const k = Math.imul(
      ((data[o + 3] & 255) << 24) | (data[o] & 255) | ((data[o + 1] & 255) << 8) | ((data[o + 2] & 255) << 16),
      -862048943)
    h ^= Math.imul((k >>> 17) | (k << 15), 461845907)
    h = Math.imul((h >>> 19) | (h << 13), 5) - 430675100
  }
  let k1 = 0
  const r = len & 3
  const o = n << 2
  if (r === 3) k1 = ((data[o + 2] & 255) << 16) ^ ((data[o + 1] & 255) << 8) ^ (data[o] & 255)
  else if (r === 2) k1 = ((data[o + 1] & 255) << 8) ^ (data[o] & 255)
  else if (r === 1) k1 = data[o] & 255
  if (r > 0) h ^= Math.imul((k1 << 15) | (k1 >>> 17), 461845907)
  h ^= len
  h = Math.imul(h ^ (h >>> 16), 2246822507 | 0)
  h = Math.imul(h ^ (h >>> 13), 3266489909 | 0)
  return (h ^ (h >>> 16)) >>> 0
}

/** 响应节点：状态码 + 消息 + 业务数据，全部大端 */
function parse (buf: Uint8Array): Node[] {
  const out: Node[] = []
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  let i = 10
  while (i < buf.length) {
    const t = buf[i++]
    if (t === 1) {
      out.push({ t, v: dv.getInt32(i) })
      i += 4
    } else if (t === 2) {
      out.push({ t, v: dv.getBigInt64(i) })
      i += 8
    } else if (t === 3 || t === 4) {
      const l = (buf[i] << 8) | buf[i + 1]
      i += 2
      out.push({ t, v: t === 3 ? Buffer.from(buf.subarray(i, i + l)).toString('utf8') : buf.subarray(i, i + l) })
      i += l
    } else if (t === 5) {
      out.push({ t, v: buf[i++] === 1 ? 1 : 0 })
    } else {
      break
    }
  }
  return out
}

class Badger {
  private readonly so: SoSigner
  private readonly bridge: number
  private readonly did: string

  constructor (did: string) {
    const dir = assetDir('libbdbadger.so')
    this.did = did
    this.so = new SoSigner({
      cold: { soPath: join(dir, 'libbdbadger.so'), libDir: join(dir, 'lib64'), deviceId: did, installId: '' },
      url: '',
      ts: 0,
    })
    this.so.coldStart()
    this.bridge = this.so.makeHandle({ kind: 'object', val: 'bridge' })
    // initCore 两种参数形态都要跑，否则后续 updateDevice 找不到上下文
    this.call(2000799499, [32, 33])
    this.call(2000799499, [32, 1, 0, 0, 0, 7, 33])
    this.call(1821380370, str('/data/user/0/com.ss.android.ugc.aweme'))
    this.call(1519260272, str(''))
  }

  /** 生成一份与当前设备绑定的登录场景报告；失败时降级为空（a0_ 才是必需证据） */
  report (): string {
    try {
      const ts = Date.now()
      const key = String(m2(Buffer.from(this.did, 'utf8')))
      const ch = this.call(770215073, bytes(Buffer.from(key + ts, 'utf8')))
      const challenge = String(Number(ch[2]?.v ?? 0) >>> 0)
      this.call(224529259, str(this.did))
      const nodes = this.call(938517046, [...str(challenge), ...int(SCENE)])
      const payload = nodes[4]?.v
      return typeof payload === 'string' ? payload : ''
    } catch {
      return ''
    }
  }

  private call (op: number, payload: number[]): Node[] {
    const handle = this.so.makeHandle({
      kind: 'bytearray',
      val: new Uint8Array([1, 0, ...be(op), ...be(payload.length), ...payload]),
    })
    const r = this.so.coldFn('a', [this.so.coldEnvAddr, this.bridge, handle, 0])
    const o = this.so.readHandle(r)
    if (!o || o.kind !== 'bytearray') throw new Error(`badger op ${op} 无返回`)
    return parse(o.val as Uint8Array)
  }
}

/** dtrait_pk1 是 Base64(PEM)，PEM 里是 PKCS#1 RSA 公钥 DER */
function pubKey (b64: string) {
  const pem = Buffer.from(b64, 'base64').toString('utf8')
  const body = pem.replace(/-----BEGIN[^-]+-----|-----END[^-]+-----/g, '').replace(/\s+/g, '')
  return createPublicKey({ key: Buffer.from(body, 'base64'), format: 'der', type: 'pkcs1' })
}

/** a0_：RSA/ECB/PKCS1(mmap + "_" + 秒)，前缀取服务端下发的 dtrait_pk1_version */
function proof (ids: Ids, ms: number): string {
  if (!ids.dtrait_pk1) return ''
  const raw = mmap(ids.device_id, ids.dtrait_version ?? 0, 'device_register')
  const plain = Buffer.concat([Buffer.from(raw), Buffer.from(`_${Math.floor(ms / 1000)}`)])
  const enc = publicEncrypt({ key: pubKey(ids.dtrait_pk1), padding: constants.RSA_PKCS1_PADDING }, plain)
  return `${ids.dtrait_pk1_version || 'a0'}_${enc.toString('base64')}`
}

/** 真机同一设备一小时内复用同一份报告，这里按进程缓存；a0_ 每次请求现算，时间戳才新鲜 */
const reports = new Map<string, string>()

export function dtrait (ids: Ids): Dtrait {
  const ms = Date.now()
  let data = reports.get(ids.device_id)
  if (data === undefined) {
    data = ids.device_id ? new Badger(ids.device_id).report() : ''
    reports.set(ids.device_id, data)
  }
  return { payload: proof(ids, ms), signal: String(ms), data, scene: String(SCENE) }
}
