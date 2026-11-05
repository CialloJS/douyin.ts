import { createHash } from 'node:crypto'
import type { RawData } from 'ws'
import { cmd, ws } from '../session/codes.js'
import { ANDROID_UA } from './profile.js'

/** 指数退避：1s, 2s, 4s, ... 封顶 30s */
export function reconnectDelay (attempt: number): number {
  return Math.min(30_000, 1_000 * 2 ** Math.max(0, attempt - 1))
}

/** Cookie 串取值：解码失败时保留原串（签名/头透传比抛错更重要） */
export function cookieValue (cookies: string, name: string): string | undefined {
  const entry = cookies.split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`))
  if (!entry) return undefined
  const value = entry.slice(name.length + 1)
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

/** WS 握手 URL：access_key 由 uid 派生，设备身份全部在 query */
export function wsUrl (userId: string, now = Date.now()): string {
  const accessKey = createHash('md5').update(`9${cmd.appKey}${userId}${cmd.salt}`).digest('hex')
  const params = new URLSearchParams({
    aid: '1128', fpid: '9', sdk_version: '3', device_id: userId, iid: userId,
    access_key: accessKey, pl: '0', ne: '1', version_code: '280400', version_name: '28.4.0',
    update_version_code: '28409900', platform: '0', monitor_service_id_list: '[]',
    is_background: '0', 'ping-interval': '30', qos_level: '2', qos_sdk_version: '2',
    ttnet_ignore_offline: '1', ws_connect_protocol: '0', device_platform: 'android', os: 'android',
    app_name: 'aweme', package: 'com.ss.android.ugc.aweme', channel: 'douyinweb1_64', ac: 'wifi',
    language: 'zh', device_type: '24031PN0DC', device_brand: 'XIAOMI', os_api: '34', os_version: '14',
    ts: String(Math.floor(now / 1000)), _rticket: String(Math.floor(now / 1000) * 1000),
  })
  return `${cmd.frontier}?${params}`
}

/** WS 握手头：会话 Cookie 与前端固定能力标记；tlb/mfa 值来自 Cookie */
export function wsHeaders (cookies: string): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': ANDROID_UA,
    Origin: cmd.host,
    Cookie: cookies,
    'x-support-qos2': ws.qos,
    'x-support-ack': ws.ack,
    'sdk-version': ws.sdk,
    'passport-sdk-version': ws.passport,
    'X-SS-DP': ws.dp,
    'x-tt-store-region': ws.region,
    'x-tt-store-region-src': ws.regionSrc,
    'x-bd-kmsv': ws.kmsv,
  }
  const tlbTag = cookieValue(cookies, 'session_tlb_tag')
  const mfaToken = cookieValue(cookies, 'passport_mfa_token')
  if (tlbTag) headers['session-tlb-tag'] = tlbTag
  if (mfaToken) headers['x-tt-passport-mfa-token'] = mfaToken
  return headers
}

/** ws 的 RawData 三种形态（Buffer/数组/ArrayBuffer）统一为字节 */
export function toBytes (data: RawData): Uint8Array {
  if (Buffer.isBuffer(data)) return data
  return Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data)
}
