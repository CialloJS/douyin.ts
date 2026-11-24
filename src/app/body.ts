/** Passport 登录请求体构造：表单串拼接、手机号规范化、MFA 与扫码表单 */
import { xor5Hex } from './codec.js'
import type { Time } from './conf.js'
import type { CaptchaCredential, Dev, Ids, MfaCtx } from './types.js'

type Pair = [string, unknown]

/** 部分字段已手工编码（mobile 的 %2B86），不能走 encodeURIComponent */
function enc (v: unknown): string {
  return encodeURIComponent(String(v))
}

function pairs (list: Pair[]): string {
  return list.map(([k, v]) => `${k}=${enc(v)}`).join('&')
}

/** 手机号统一成 +86xxxxxxxxxxx（真机 body 带 +86） */
export function normalizeMobile (mobile: string): string {
  const m = mobile.replace(/\s/g, '')
  if (m.startsWith('+')) return m
  return m.length === 11 ? `+86${m}` : m
}

/** 验证码登录第一步：mobile/send_code；type(24)/unbind_exist 走 XOR，mobile 已手工编码 */
export function buildSendCode (mobile: string, cred: CaptchaCredential = {}): string {
  const list: Array<[string, string]> = [
    ['is_vcd', '1'],
    ['reg_cookie_opt', 'true'],
    ['ttnet_sdk_version', '4.2.301.9-douyin'],
    ['auto_read', '0'],
    ['auth_sdk_version', '4.7.7-rc.23'],
    ['mix_mode', '1'],
    ['account_app_language', 'zh'],
    ['mobile', `%2B86+${enc(mobile.replace(/\s/g, '').replace(/^\+86/, ''))}`],
  ]
  if (cred.captcha) list.push(['captcha', enc(cred.captcha)])
  if (cred.sharkTicket) list.push(['shark_ticket', enc(cred.sharkTicket)])
  list.push(
    ['language', 'zh'],
    ['multi_login', '1'],
    ['type', xor5Hex('24')],
    ['sec_sdk_version', '67765248'],
    ['account_sdk_source', 'app'],
    ['passport_support_flow', 'choose_account%2Ccaptcha%2Creal_name_check%2Cverify'],
    ['unbind_exist', xor5Hex('0')],
    ['verify_sdk_version', '4.2.1.cn'],
    ['is_from_iesaccountsaas', '1'],
  )
  return list.map(([k, v]) => `${k}=${v}`).join('&')
}

/** mobile/sms_login：code 与 mobile 都走 XOR */
export function buildSmsLogin (code: string, mobileTicket: string, mobile: string): string {
  return `is_vcd=1&safe_mobile_register_to_login=true&reg_cookie_opt=true&auth_opposite=1&ttnet_sdk_version=4.2.301.9-douyin&auth_sdk_version=4.7.7-rc.23&code=${xor5Hex(code)}&mobile_ticket=${enc(mobileTicket)}&mix_mode=1&account_app_language=zh&mobile=${xor5Hex(normalizeMobile(mobile))}&language=zh&user_api_need_combine=1&multi_login=1&sec_sdk_version=67765248&account_sdk_source=app&passport_support_flow=choose_account%2Ccaptcha%2Creal_name_check%2Cverify&verify_sdk_version=4.2.1.cn&is_from_iesaccountsaas=1&is_vcd_multi_account=1`
}

/** user/login：密码登录入口（MFA 前后各调一次） */
export function buildPwdLogin (mobile: string, password: string, opts: { ctx?: MfaCtx; verifyWay?: string } & CaptchaCredential = {}): string {
  const list: Pair[] = [
    ['mobile', xor5Hex(normalizeMobile(mobile))],
    ['password', xor5Hex(password)],
    ['mix_mode', '1'],
  ]
  const d = opts.ctx
  if (opts.captcha) list.push(['captcha', opts.captcha])
  if (opts.sharkTicket) list.push(['shark_ticket', opts.sharkTicket])
  if (d) {
    const ev = obj(d.event_params)
    const cp = obj(d.common_params)
    const way = opts.verifyWay ?? 'mobile_sms_verify'
    list.push(
      ['verify_way', way],
      ['std_verify_way', way],
      ['verify_scene', String(ev.verify_scene ?? cp.copywriting_key ?? 'self_secondary_verify')],
    )
    if (opts.mobileTicket) list.push(['mobile_ticket', opts.mobileTicket])
    if (d.encrypt_uid) list.push(['encrypt_uid', d.encrypt_uid])
    if (d.not_login_ticket) list.push(['not_login_ticket', d.not_login_ticket])
    for (const [k, v] of Object.entries(obj(d.biz_params))) if (v !== undefined && v !== null && v !== '') list.push([k, String(v)])
  }
  return pairs(list)
}

/** account/verify：密码二次验证（无 type / mobile_ticket / scene，三者自造会 1204） */
export function buildVerify (d: MfaCtx, password: string): string {
  const ev = obj(d.event_params)
  const cp = obj(d.common_params)
  const scene = String(ev.verify_scene ?? cp.copywriting_key ?? 'self_secondary_verify')
  const list: Pair[] = [
    ['is_vcd', '1'],
    ['reg_cookie_opt', 'true'],
    ['copywriting_key', String(cp.copywriting_key ?? scene)],
    ['new_authn_sdk_version', '1.2.0-beta.1'],
    ['ttnet_sdk_version', '4.2.301.9-douyin'],
    ['auth_sdk_version', '4.7.7-rc.23'],
    ['mix_mode', '1'],
    ['account_app_language', 'zh'],
    ['verify_scene', scene],
    ['language', 'zh'],
    ['multi_login', '1'],
    ['encrypt_uid', d.encrypt_uid ?? ''],
    ['verify_reason', String(ev.verify_reason ?? scene)],
    ['sec_sdk_version', '67765248'],
    ['password', xor5Hex(password)],
    ['std_verify_way', 'pwd_verify'],
    ['account_sdk_source', 'app'],
    ['passport_support_flow', 'choose_account,captcha,real_name_check,verify'],
    ['verify_sdk_version', '4.2.1.cn'],
  ]
  if (cp.ies_safety_diversion_tag) list.push(['ies_safety_diversion_tag', String(cp.ies_safety_diversion_tag)])
  list.push(['is_from_iesaccountsaas', '1'], ['verify_way', 'pwd_verify'])
  return pairs(list)
}

/** MFA 公共表单：缺 $$secondVerificationRequestCommonParams 会 1204 */
function mfaForm (d: MfaCtx, actType: string, extra: Pair[] = [], way = 'mobile_sms_verify'): Pair[] {
  const ev = obj(d.event_params)
  const cp = obj(d.common_params)
  const scene = String(ev.verify_scene ?? cp.copywriting_key ?? 'self_secondary_verify')
  const list: Pair[] = [
    ['is_vcd', '1'],
    ['reg_cookie_opt', 'true'],
    ['copywriting_key', cp.copywriting_key ?? scene],
    ['new_authn_sdk_version', '1.2.0-beta.1'],
    ['ttnet_sdk_version', '4.2.301.9-douyin'],
    ['auth_sdk_version', '4.7.7-rc.23'],
    ...extra,
    ['mix_mode', '1'],
    ['account_app_language', 'zh'],
    ['verify_scene', scene],
    ['language', 'zh'],
    ['multi_login', '1'],
  ]
  if (actType) list.push(['type', xor5Hex(actType)])
  list.push(
    ['encrypt_uid', d.encrypt_uid ?? ''],
    ['verify_reason', ev.verify_reason ?? scene],
    ['sec_sdk_version', '67765248'],
    ['std_verify_way', way],
    ['account_sdk_source', 'app'],
    ['passport_support_flow', 'choose_account,captcha,real_name_check,verify'],
    ['verify_sdk_version', '4.2.1.cn'],
  )
  if (cp.ies_safety_diversion_tag) list.push(['ies_safety_diversion_tag', cp.ies_safety_diversion_tag])
  list.push(['is_from_iesaccountsaas', '1'], ['verify_way', way])
  if (ev.std_verify_scene) list.push(['std_verify_scene', ev.std_verify_scene])
  if (d.verify_ticket) list.push(['verify_ticket', d.verify_ticket])
  return list
}

/** MFA 下发短信：mobile/send_code（type=22，11 位裸号） */
export function buildMfaSendCode (actType: string, d: MfaCtx, mobile11 = ''): string {
  const extra: Pair[] = []
  if (mobile11) extra.push(['mobile', mobile11])
  extra.push(['is6Digits', '1'])
  return pairs(mfaForm(d, actType, extra))
}

/** MFA 提交验证码：mobile/validate_code（type/code 走 XOR） */
export function buildValidateCode (code: string, actType: string, d: MfaCtx): string {
  return pairs(mfaForm(d, actType, [['code', xor5Hex(code)]]))
}

/** 短信上行验证：upsms/verify；无 type/mobile，靠 x-tt-passport-mfa-token 关联 */
export function buildUpSmsVerify (d: MfaCtx): string {
  return pairs(mfaForm(d, '', [], 'mobile_up_sms_verify'))
}

/** MFA 扫码取码：mobile/get_qrcode（scene=secondary_verify） */
export function buildMfaQrCodeBody (d: MfaCtx, service: string): string {
  return pairs(mfaForm(d, '', [
    ['source', 'app'],
    ['scene', 'secondary_verify'],
    ['need_record', '1'],
    ['service', service],
  ], 'qr_code_verify'))
}

/** MFA 扫码轮询：mobile/validate_by_qrcode（new → confirmed） */
export function buildMfaQrCheckBody (token: string, d: MfaCtx): string {
  return pairs(mfaForm(d, '', [
    ['token', token],
    ['scene', 'secondary_verify'],
    ['need_record', '1'],
  ], 'qr_code_verify'))
}

/** 扫码登录取码 */
export function buildQrCodeBody (service = '', source = ''): string {
  const list: Pair[] = []
  if (service) list.push(['service', service])
  list.push(['scene', '0'], ['need_logo', '1'], ['source', source], ['is_from_iesaccountsaas', '1'])
  return pairs(list)
}

/** 扫码登录轮询：真机 CheckQrConnect 只带这五个字段，source/need_logo 属于取码阶段 */
export function buildQrCheckBody (token: string, service = 'aweme.snssdk.com'): string {
  return pairs([
    ['token', token],
    ['service', service],
    ['scene', '0'],
    ['user_api_need_combine', '1'],
    ['is_from_iesaccountsaas', '1'],
  ])
}

/** MFA 通过后重放 check_qrconnect（body + biz_params + std_verify_way，不带 verify_ticket） */
export function buildQrReplayBody (token: string, service: string, source: string, d: MfaCtx, verifyTicket: string, mobileTicket = '', way = 'mobile_sms_verify'): string {
  const ev = obj(d.event_params)
  const cp = obj(d.common_params)
  const scene = String(ev.verify_scene ?? cp.copywriting_key ?? 'self_secondary_verify')
  const list: Pair[] = [
    ['token', token],
    ['service', service],
    ['scene', '0'],
    ['need_logo', '1'],
    ['source', source],
    ['is_from_iesaccountsaas', '1'],
    ['verify_way', way],
    ['std_verify_way', way],
    ['verify_scene', scene],
  ]
  if (verifyTicket) list.push(['verify_ticket', verifyTicket])
  if (mobileTicket) list.push(['mobile_ticket', mobileTicket])
  if (d.encrypt_uid) list.push(['encrypt_uid', d.encrypt_uid])
  for (const [k, v] of Object.entries(obj(d.biz_params))) {
    if (v === undefined || v === null || v === '') continue
    list.push([k, k === 'sms_code_key' ? xor5Hex(String(v)) : String(v)])
  }
  return pairs(list)
}

/** 设置-保存登录信息：device_record_status/set（2 打开 / 1 关闭） */
export function buildDeviceRecordStatus (status: 1 | 2): string {
  return pairs([
    ['is_vcd', '1'],
    ['reg_cookie_opt', 'true'],
    ['sec_sdk_version', '67765248'],
    ['ttnet_sdk_version', '4.2.301.9-douyin'],
    ['auth_sdk_version', '4.7.7-rc.23'],
    ['account_sdk_source', 'app'],
    ['user_device_record_status', String(status)],
    ['passport_support_flow', 'choose_account,captcha,real_name_check,verify'],
    ['account_app_language', 'zh'],
    ['verify_sdk_version', '4.2.1.cn'],
    ['is_from_iesaccountsaas', '1'],
    ['language', 'zh'],
    ['multi_login', '1'],
  ])
}

/** 登录成功后必调 update_token，否则 account/info 会 13（会话过期） */
export function buildUpdateToken (dev: Dev, ids: Ids, t: Time): string {
  return pairs([
    ['is_guest_mode', '0'],
    ['manifest_version_code', dev.manifestVersionCode],
    ['_rticket', t.rticket],
    ['app_type', 'normal'],
    ['is_preinstall', '0'],
    ['iid', ids.iid],
    ['channel', dev.channel],
    ['is_android_pad', '0'],
    ['device_type', dev.deviceType],
    ['language', 'zh'],
    ['cpu_support64', 'true'],
    ['host_abi', 'arm64-v8a'],
    ['resolution', dev.resolution.replace('x', '*')],
    ['update_version_code', dev.updateVersionCode],
    ['cdid', ids.cdid],
    ['minor_status', '0'],
    ['appTheme', dev.appTheme],
    ['os_api', dev.osApi],
    ['klink_egdi', ids.klink_egdi],
    ['is_android_fold', '0'],
    ['dpi', dev.dpi],
    ['ac', dev.ac],
    ['package', dev.packageName],
    ['device_id', ids.device_id],
    ['os', dev.os],
    ['mcc_mnc', dev.mccMnc],
    ['os_version', dev.osVersion],
    ['version_code', dev.versionCode],
    ['last_deeplink_update_version_code', '0'],
    ['app_name', dev.appName],
    ['version_name', dev.versionName],
    ['push_sdk', '[10,15,21,26,27]'],
    ['device_brand', dev.deviceBrand],
    ['need_personal_recommend', '1'],
    ['ssmix', dev.ssmix],
    ['device_platform', dev.devicePlatform],
    ['first_launch_timestamp', ids.first_install],
    ['aid', dev.aid],
    ['ts', t.ts],
  ])
}

/** NetworkProxyAccount：原参数 + biz_params + 额外参数（保序）；sms_code_key 走 XOR 并补 mix_mode */
export function mergeBizParams (original: string, d: MfaCtx, extra: Record<string, string> = {}): string {
  const order: string[] = []
  const m = new Map<string, string>()
  for (const [k, v] of new URLSearchParams(original)) {
    if (!m.has(k)) order.push(k)
    m.set(k, v)
  }
  for (const [k, v] of Object.entries(obj(d.biz_params))) {
    if (v === undefined || v === null || v === '') continue
    if (!m.has(k)) order.push(k)
    m.set(k, String(v))
  }
  for (const [k, v] of Object.entries(extra)) {
    if (!m.has(k)) order.push(k)
    m.set(k, v)
  }
  const smsKey = m.get('sms_code_key')
  if (smsKey) {
    m.set('sms_code_key', xor5Hex(smsKey))
    if (!m.has('mix_mode')) order.push('mix_mode')
    m.set('mix_mode', '1')
  }
  return order.map(k => `${k}=${enc(m.get(k) ?? '')}`).join('&')
}

/** 服务端常把 params 传成 JSON 串 */
function obj (v: unknown): Record<string, unknown> {
  if (!v) return {}
  if (typeof v === 'string') {
    try {
      return JSON.parse(v) as Record<string, unknown>
    } catch {
      return {}
    }
  }
  return v as Record<string, unknown>
}
