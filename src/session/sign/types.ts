/** 签名模块公共 opts/result 类型：aid/ac/bogus/frontier/qs */
import type { Preset } from './bogus.js'

export interface AidSignOpts {
  aid: string
  /** 不含 query 的 path，如 `/passport/web/get_qrcode/` */
  path: string
  /** 与查询串 `ts` 一致，默认 `noonTs()` */
  ts?: string
  appKey?: string
}

export interface ABogusOpts {
  userAgent: string
  /** 已含 sign/qs/msToken，不含 a_bogus 的 query 串 */
  query: string
  /** POST 为 on-wire x-www-form-urlencoded；GET 传 '' */
  body?: string
  screenFingerprint?: string
  bdmsPreset?: Preset
  keyVal?: number
}

export interface DesktopABogusOpts {
  userAgent: string
  query: string
  body?: string
  nowMs?: number
  random?: () => number
}

export interface AcOpts {
  /** 参与 hash 的路径或站点标识，常见 `/`、`/jingxuan`、`__ac_blank` */
  url: string
  acNonce: string
  userAgent: string
  /** Unix 秒；默认 `Math.floor(Date.now() / 1000)` */
  timestampSec?: number
}

export interface AcMsOpts {
  url: string
  acNonce: string
  userAgent: string
  /** Unix 毫秒；默认 `Date.now()` */
  timestampMs?: number
}

export interface FrontierOpts {
  userAgent?: string
}

export interface SignQsOpts {
  /** 查询参数（不含 sign / qs / msToken / a_bogus） */
  query: Record<string, string>
  /** POST body 字段；使用解码后的值（与 SDK 内存对象一致，非 URL 编码串） */
  body?: Record<string, string>
  appKey?: string
}

export interface SignQsResult {
  sign: string
  qs: string
}

export interface QueryOpts {
  /** Unix 秒；默认 `noonTs()` */
  ts?: string
  bizTraceId?: string
  accountSdkSourceInfo?: string
  isNewLogin?: string
  next?: string
  extra?: Record<string, string>
}

export interface SignedQuery {
  query: Record<string, string>
  search: string
}

export interface SignExtras {
  /** Passport SDK appKey */
  appKey?: string
  msToken?: string
  /** 手动覆盖时跳过本地计算 */
  aBogus?: string
  userAgent?: string
  enableABogus?: boolean
  /** POST 的 on-wire form（`encodeForm`）；GET 传 '' */
  bodyWire?: string
  screenFingerprint?: string
  bdmsPreset?: Preset
  aBogusVariant?: 'creator' | 'jumpbyte-desktop'
}

export interface PassportQueryOpts {
  /** 服务端注册的桌面设备 id */
  deviceId: string
  /** 桌面客户端 iid（未注册为 '0'） */
  installId: string
  accountSdkSourceInfo?: string
  bizTraceId?: string
  next?: string
  /** need_logo / need_short_url / fp 等 login scope 追加项 */
  extra?: Record<string, string>
}
