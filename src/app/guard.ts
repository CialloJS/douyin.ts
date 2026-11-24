/** ticket-guard v3 设备证明：优先用同源 profile 材料，缺失时才按设备稳定标识派生 */
import { createECDH, createHash, createHmac, createPrivateKey, sign } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, isAbsolute, join } from 'node:path'
import type { KeyObject } from 'node:crypto'
import type { Dev, Ids } from './types.js'
import type { HeaderPair } from './sign/index.js'

/** 真机服务端证书序列号；boot 时原样回带，服务端据此选验签证书 */
const SN = '533240336124694022040808462028007165443034493949'
/** 派生证书没有服务端共享的 ecdh 键，扫码确认后 HMAC 必然对不上 */
const HMAC_KEY = Buffer.alloc(32, 7)

interface Key {
  key: KeyObject
  pub: Buffer
}

interface Guard {
  cert: string
  reeKey: string
  tee: KeyObject
  ree: KeyObject
}

interface TgFile {
  ree_private_key?: string
  ecdh_key?: string
  display_os_version?: string
  tee?: { pub_key?: string; private_key_path?: string; sec_ts?: string; server_cert_sn?: string }
  tickets?: Record<string, { ts_sign_ree?: string }>
}

interface Tg {
  cert: string
  reeKey: string
  tee: KeyObject
  ree: KeyObject
  ecdh: Buffer
  sec: string
  sn: string
  os: string
  tickets: Record<string, { ts_sign_ree?: string }>
}

const cache = new Map<string, Guard>()
let tg: Tg | null | undefined

/** 私钥标量转 P-256 KeyObject；最高位压掉保证落在曲线阶内 */
function keyOf (hex: string): Key {
  const d = Buffer.from(hex, 'hex')
  d[0] &= 0x7f
  const ecdh = createECDH('prime256v1')
  ecdh.setPrivateKey(d)
  const pub = ecdh.getPublicKey()
  const key = createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: d.toString('base64url'),
      x: pub.subarray(1, 33).toString('base64url'),
      y: pub.subarray(33, 65).toString('base64url'),
    },
    format: 'jwk',
  })
  return { key, pub }
}

/**
 * profile 的证书、ecdh 键与 sec-ts 必须来自同一次真机登记：
 * 服务端按 device_id 记住登记材料，跨设备拼装或派生都会在扫码确认阶段判 7。
 */
function load (): Tg | null {
  if (tg !== undefined) return tg
  tg = null
  const file = process.env.DY_TG_PROFILE ?? 'assets/tg.json'
  if (!existsSync(file)) return tg
  const raw = JSON.parse(readFileSync(file, 'utf8')) as TgFile
  const t = raw.tee ?? {}
  const path = t.private_key_path
  if (!raw.ree_private_key || !t.pub_key || !path) return tg
  const pem = isAbsolute(path) ? path : join(dirname(file), path)
  if (!existsSync(pem)) return tg
  const ree = keyOf(raw.ree_private_key)
  tg = {
    cert: Buffer.from(`pub.${t.pub_key}`, 'utf8').toString('base64'),
    reeKey: ree.pub.toString('base64'),
    tee: createPrivateKey(readFileSync(pem)),
    ree: ree.key,
    ecdh: Buffer.from(raw.ecdh_key ?? '', 'base64'),
    sec: t.sec_ts ?? '',
    sn: t.server_cert_sn ?? SN,
    os: raw.display_os_version ?? '',
    tickets: raw.tickets ?? {},
  }
  return tg
}

function pair (seed: string, tag: string): Key {
  return keyOf(createHash('sha256').update(`${tag}:${seed}`, 'utf8').digest('hex'))
}

function guard (ids: Ids): Guard {
  const p = load()
  if (p) return { cert: p.cert, reeKey: p.reeKey, tee: p.tee, ree: p.ree }
  const seed = ids.clientudid || ids.openudid || ids.cdid
  const hit = cache.get(seed)
  if (hit) return hit
  const tee = pair(seed, 'tee')
  const ree = pair(seed, 'ree')
  const g: Guard = {
    cert: Buffer.from(`pub.${tee.pub.toString('base64')}`, 'utf8').toString('base64'),
    reeKey: ree.pub.toString('base64'),
    tee: tee.key,
    ree: ree.key,
  }
  cache.set(seed, g)
  return g
}

/** IM 信封 PASSPORT_CERT_AUTH(4) 的 cert 与 ree 公钥，必须与请求头同源 */
export function zt (ids: Ids): { cert: string; reeKey: string } {
  const g = guard(ids)
  return { cert: g.cert, reeKey: g.reeKey }
}

/** profile 的 sec-ts 与 tee 证书同源；重新 boot 会换成派生证书，反倒制造不一致 */
export function tgSec (): string {
  return load()?.sec ?? ''
}

/** client-data：字段顺序与真机 Gson 序列化一致，服务端按原文验 HMAC 与签名 */
export function clientData (ids: Ids, path: string, ticket: string, ts: number): string {
  const p = load()
  const tsSign = p
    ? (p.tickets[path]?.ts_sign_ree ?? '')
    : `ts.1.${sign('sha256', Buffer.from(`ts.1.${ts}`, 'utf8'), {
        key: guard(ids).ree,
        dsaEncoding: 'ieee-p1363',
      }).toString('hex')}`
  const reqSign = createHmac('sha256', p?.ecdh.length === 32 ? p.ecdh : HMAC_KEY)
    .update(`ticket=${ticket}&path=${path}&timestamp=${ts}`)
    .digest('base64')
  return Buffer.from(
    JSON.stringify({
      req_content: 'ticket,path,timestamp',
      timestamp: ts,
      ts_sign: '',
      ts_sign_ree: tsSign,
      req_sign: '',
      req_sign_ree: reqSign,
    }),
    'utf8',
  ).toString('base64')
}

/** static-sign：真机直接用 tee 私钥对 sec-ts 原文做 SHA256withECDSA；额外哈希或加前缀都会验签失败（响应头 1105） */
export function staticSign (ids: Ids, sec: string): string {
  return sign('sha256', Buffer.from(sec, 'utf8'), { key: guard(ids).tee }).toString('base64')
}

/** 注册请求只带三件套：服务端借此把公钥绑定到 device_id，后续业务请求才认 static-sign */
export function regHead (ids: Ids, sec: string): HeaderPair[] {
  return [
    ['bd-ticket-guard-client-cert', guard(ids).cert],
    ['bd-ticket-guard-static-sign', staticSign(ids, sec)],
    ['bd-ticket-guard-sec-ts', sec],
  ]
}

/** 设备证明公共头：boot 用迭代 3 并追加 client-data，业务请求用迭代 2 并追加 sec-ts */
export function head (dev: Dev, ids: Ids, iteration: 2 | 3, extra: HeaderPair[] = []): HeaderPair[] {
  const g = guard(ids)
  const p = load()
  return [
    ['bd-ticket-guard-version', '3'],
    ['bd-ticket-guard-tee-status', '1'],
    ['bd-ticket-guard-server-cert-sn', p?.sn || SN],
    ['bd-ticket-guard-display-os-version', p?.os || dev.romVersion],
    ['bd-ticket-guard-client-cert', g.cert],
    ['bd-ticket-guard-ree-public-key', g.reeKey],
    ['bd-ticket-guard-iteration-version', String(iteration)],
    ...extra,
  ]
}
