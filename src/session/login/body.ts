/** Passport 登录请求体组装:check_qrconnect 与 MFA 表单、biz 透传字段。另含签名附加值构造。 */
import { browserInfo, encodeBrowserInfo } from '../sign/browser.js'
import { randomMsToken } from '../sign/qs.js'
import { passport } from '../sign/const.js'
import type { SignExtras } from '../sign/types.js'
import type { Http } from '../http.js'
import { bogus, ck, fld, qr, way } from './codes.js'
import type { Challenge } from './types.js'

export function qrBody (token: string): Record<string, string> {
  return {
    need_logo: qr.needLogo,
    need_short_url: qr.needShort,
    is_frontier: qr.frontier,
    token,
    is_new_login: qr.newLogin,
    next: qr.next,
  }
}

export function mfaBody (challenge: Challenge, verifyWay: string, extra: Record<string, string>): Record<string, string> {
  const biz = challenge.biz_params ?? {}
  const common = challenge.common_params ?? {}
  const value = (source: Record<string, unknown>, key: string, fallback = ''): string => {
    const candidate = source[key]
    return candidate == null || candidate === '' ? fallback : String(candidate)
  }
  return {
    mix_mode: fld.mixMode,
    // 绑定手机短信走桌面场景 3737;辅助手机/上行短信走 web 场景 363c;密码验证无 type 字段
    ...(verifyWay === way.password ? {} : { type: verifyWay === way.sms ? fld.desktopType : fld.webType }),
    encrypt_uid: challenge.encrypt_uid ?? '',
    verify_ticket: '',
    copywriting_key: value(common, 'copywriting_key', fld.copywriting),
    ies_safety_diversion_tag: value(common, 'ies_safety_diversion_tag', fld.diversion),
    new_verify_flow: value(common, 'new_verify_flow'),
    std_verify_flow_id: value(biz, 'std_verify_flow_id', value(common, 'std_verify_flow_id')),
    std_verify_scene: value(biz, 'std_verify_scene', fld.scene),
    std_verify_template: value(biz, 'std_verify_template', fld.template),
    std_verify_token: value(biz, 'std_verify_token', value(common, 'std_verify_token')),
    std_verify_type: value(biz, 'std_verify_type', fld.type),
    std_verify_way: verifyWay,
    ...extra,
    aid: passport.aid,
    new_authn_sdk_version: fld.sdk,
  }
}

/** MFA 校验通过后,轮询 check_qrconnect 需要携带的 biz 参数 */
export function pickBiz (params?: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {}
  if (!params) return result
  for (const key of fld.bizKeys) {
    const value = params[key]
    if (value != null) result[key] = String(value)
  }
  return result
}

/** account_sdk_source_info:优先 Cookie,缺失时以 browserInfo 模板编码并回写 */
export function sdkSourceInfo (http: Http): string {
  const stored = http.jar.get(ck.source)
  if (stored) return stored
  const info = encodeBrowserInfo(browserInfo(http.deviceId))
  http.jar.set(ck.source, info)
  return info
}

export function signExtras (http: Http, bodyWire = ''): SignExtras {
  const extras: SignExtras = {
    userAgent: http.ua,
    // 桌面登录页走 jumpbyte desktop 变体 a_bogus(HAR 全链路实证)
    appKey: passport.appKey,
    aBogusVariant: bogus,
    bodyWire,
  }
  const msToken = http.jar.get(ck.msToken)
  // 官方每轮携带随机 msToken,不参与 sign
  extras.msToken = msToken ?? randomMsToken()
  return extras
}
