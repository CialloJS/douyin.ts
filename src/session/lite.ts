/** desktop lite Passport 传输层（imdesktop 域 + jumpbyte a_bogus），扫码 MFA 与安全验证共用 */
import { err } from '../error.js'
import { aBogusDesktop } from './sign/bogus.js'
import { encodeDesktopParams, randomHex, randomMsToken } from './sign/qs.js'
import { im, lite, passport } from './sign/const.js'
import type { Http } from './http.js'
import type { MfaRes } from '../types.js'

/** 未注册设备时 lite 接口的进程内随机 DID 兜底 */
const fallbackDid = randomHex(16)

/** 字段顺序对齐 jumpbyte canonical，服务端按原序验签 */
function liteQuery (deviceId: string): Record<string, string> {
  return {
    passport_jssdk_version: lite.jssdk,
    passport_jssdk_type: lite.type,
    is_from_ttaccountsdk: lite.fromSdk,
    aid: passport.aid,
    language: lite.lang,
    account_app_language: lite.appLang,
    is_new_login: lite.newLogin,
    is_from_iesaccountsaas: lite.fromSaas,
    biz_trace_id: randomHex(8),
    new_authn_sdk_version: lite.authn,
    device_id: deviceId,
    iid: lite.iid,
    version_code: im.version,
    device_platform: lite.platform,
  }
}

export async function form (http: Http, path: string, body: Record<string, string>): Promise<MfaRes> {
  const query = { ...liteQuery(http.hasDevice() ? http.deviceId : fallbackDid), msToken: randomMsToken() }
  const bodyWire = encodeDesktopParams(body)
  const queryWire = encodeDesktopParams(query)
  const bogus = aBogusDesktop({ userAgent: http.ua, query: queryWire, body: bodyWire })
  const url = `${passport.origin}${path}?${queryWire}&a_bogus=${encodeURIComponent(bogus)}`
  const res = await http.json<MfaRes>(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Referer: `${im.origin}/` },
    body: bodyWire,
  })
  if (!res.ok) return err(res.data)
  return res.data
}
