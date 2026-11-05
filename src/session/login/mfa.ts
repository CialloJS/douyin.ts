/** 短信 / 上行短信 / 密码二次验证:方式选择、发码、校验与上行短信轮询 */
import { err } from '../../error.js'
import { mixEncode } from '../sign/mix.js'
import { form } from '../lite.js'
import type { Http } from '../http.js'
import type { MfaRes } from '../../types.js'
import { fld, msg, path, st, time, way } from './codes.js'
import { mfaBody, pickBiz } from './body.js'
import type { Challenge, CheckData, LoginOpts, VerifyWay } from './types.js'

export function sleep (ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/** 验证方式优先级:安全手机短信 > 绑定手机短信 > 上行短信(用安全手机发短信)> 登录密码 */
export function selectWay (data: CheckData): VerifyWay | undefined {
  const ways = data.verify_ways ?? []
  return way.order
    .map(name => ways.find(w => w.verify_way === name))
    .find(Boolean)
}

interface Flow {
  http: Http
  data: CheckData
  challenge: Challenge
  selected: VerifyWay
  name: string
  opts: LoginOpts
}

/** 验证方式分发:方式与流程解耦,新增方式只加一行 */
const flows: Record<string, (flow: Flow) => Promise<void>> = {
  [way.upSms]: flow => upSms(flow.http, flow.challenge, flow.selected, flow.opts.onStatus),
  [way.password]: flow => password(flow.http, flow.challenge, flow.opts),
  [way.assistSms]: sms,
  [way.sms]: sms,
}

/** 短信/密码二次验证:按优先级选择方式,通过后返回轮询需携带的 biz 参数 */
export async function mfa (http: Http, data: CheckData, opts: LoginOpts): Promise<Record<string, string>> {
  const challenge: Challenge = {
    encrypt_uid: data.encrypt_uid,
    biz_params: data.biz_params,
    common_params: data.common_params,
  }
  const ways = data.verify_ways ?? []
  // 方式选择权交给调用方:回调返回 undefined 或未提供回调时按内置优先级
  const chosen = await opts.onVerifyWays?.(ways)
  const selected = chosen == null
    ? selectWay(data)
    : ways.find(w => w.verify_way === chosen)
  if (!selected?.verify_way) {
    if (chosen != null) err({ chosen, verify_ways: ways })
    err({ verify_ways: ways })
  }
  const name = selected.verify_way
  // 未登记的方式按短信流程处理,与官方默认行为一致
  await (flows[name] ?? sms)({ http, data, challenge, selected, name, opts })
  return pickBiz(data.biz_params)
}

/** 短信验证码流程:依次尝试发码(选中的方式 → 辅助手机兜底),被拒时回退上行短信 */
async function sms (flow: Flow): Promise<void> {
  const { http, data, challenge, selected, name, opts } = flow
  if (!opts.onMfa) err({ onMfa: false })
  const candidates = name === way.sms ? [way.sms, way.assistSms] : [name]
  let sent: MfaRes | undefined
  let used: string | undefined
  for (const candidate of candidates) {
    const res = await sendCode(http, challenge, candidate)
    sent = res
    if (res.message === fld.smsOk) {
      used = candidate
      break
    }
  }
  if (sent?.message !== fld.smsOk || used === undefined) {
    // 发码被拒:优先回退上行短信验证
    const falling = (data.verify_ways ?? []).find(w => w.verify_way === way.upSms)
    if (falling?.verify_way) {
      await opts.onStatus?.(`发码被拒(${sent?.message ?? 'unknown'}${sent?.data.description ? `: ${sent.data.description}` : ''}),改用上行短信验证`)
      await upSms(http, challenge, falling, opts.onStatus)
      return
    }
    err(sent)
  }
  if (used !== name) await opts.onStatus?.(msg.assistSwitch)
  const maskedMobile = sent.data.mobile ?? selected.mobile
  const code = await opts.onMfa({ kind: 'sms', maskedMobile: maskedMobile != null ? String(maskedMobile) : undefined })
  const validated = await validateCode(http, challenge, used, code)
  if (!validated.data.ticket) err(validated)
  await opts.onStatus?.(st.verified)
}

/** 登录密码验证:无需发码,直接提交密码 */
async function password (http: Http, challenge: Challenge, opts: LoginOpts): Promise<void> {
  if (!opts.onMfa) err({ onMfa: false })
  const input = await opts.onMfa({ kind: 'password' })
  if (!input) err({ password: input })
  const validated = await validatePassword(http, challenge, input)
  if (!validated.data.ticket) err(validated)
  await opts.onStatus?.(msg.pwdOk)
}

/** 上行短信验证:用安全手机编辑指定短信发送到服务端号码,轮询 validate_code 等确认 */
async function upSms (
  http: Http,
  challenge: Challenge,
  selected: VerifyWay,
  onStatus?: (s: string) => void | Promise<void>,
): Promise<void> {
  const content = selected.sms_content || fld.defaultSms
  await onStatus?.(`请用安全手机(${selected.mobile ?? ''})编辑短信"${content}"发送到 ${selected.channel_mobile ?? ''}`)
  const deadline = Date.now() + time.upTimeout
  while (Date.now() < deadline) {
    await sleep(time.upPoll)
    let res: MfaRes
    try {
      res = await validateCode(http, challenge, selected.verify_way ?? way.upSms)
    } catch {
      continue
    }
    if (res.data.ticket) {
      await onStatus?.(msg.smsOk)
      return
    }
  }
  err({ timeout: time.upTimeout })
}

function sendCode (http: Http, challenge: Challenge, verifyWay: string): Promise<MfaRes> {
  return form(http, path.send, mfaBody(challenge, verifyWay, { is6Digits: fld.sixDigits }))
}

function validateCode (http: Http, challenge: Challenge, verifyWay: string, code?: string): Promise<MfaRes> {
  // 3737 桌面场景用 mixEncode,363c web 场景用 xorHex
  const encoded = code == null
    ? undefined
    : verifyWay === way.sms ? mixEncode(code) : xorHex(code)
  return form(http, path.validate, mfaBody(challenge, verifyWay, encoded != null ? { code: encoded } : {}))
}

/**
 * 登录密码二次验证(pwd_verify,逆向自 second-verification-web.js):
 * POST /passport/web/account/verify/,password 字段 xorHex(Xor5+hex)编码 + mix_mode=1,
 * 无 type/send_code 步骤,成功返回 data.ticket。
 */
function validatePassword (http: Http, challenge: Challenge, passwordText: string): Promise<MfaRes> {
  return form(http, path.password, mfaBody(challenge, way.password, { password: xorHex(passwordText) }))
}

/** code_encrypt:UTF-8 每字节 ^5 后的两位 hex(363c 场景配套) */
function xorHex (s: string): string {
  const hex = '0123456789abcdef'
  let out = ''
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0
    const bytes = c <= 0x7f ? [c]
      : c <= 0x7ff ? [0xc0 | ((c >> 6) & 0x1f), 0x80 | (c & 0x3f)]
        : c <= 0xffff ? [0xe0 | ((c >> 12) & 0x0f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)]
          : []
    for (const b of bytes) out += hex[(b ^ 5) >> 4] + hex[(b ^ 5) & 15]
  }
  return out
}
