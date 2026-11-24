/** App 登录状态机：只做请求编排，error_code 由上层判断 */
import type { Auth } from './auth.js'
import type { Dev, Ids, LoginData, Envelope, MfaCtx, CaptchaCredential } from './types.js'
import type { Res } from './http.js'
import { send, type Send } from './api.js'
import { nowTime } from './conf.js'
import {
  buildDeviceRecordStatus,
  buildMfaQrCheckBody,
  buildMfaQrCodeBody,
  buildMfaSendCode,
  buildPwdLogin,
  buildQrCheckBody,
  buildQrCodeBody,
  buildQrReplayBody,
  buildSendCode,
  buildSmsLogin,
  buildUpdateToken,
  buildUpSmsVerify,
  buildValidateCode,
  buildVerify,
  mergeBizParams,
  normalizeMobile,
} from './body.js'

/** 扫码接口固定参数（缺 service 会返回 error_code 3） */
export const QR_SERVICE = 'https://aweme.snssdk.com'

/**
 * 登录入口用 s=-1：真机 hook 抄录与参考项目成功样例都是该值，此时服务端下发
 * shark_admin 完整决策（带加密 detail）。s=0/2 只会下发 verify_center 的 10 字段
 * 简化决策，没有 detail，滑块 verify 必然被判 5014。
 */
const TAG = 'n=0;s=-1;p=0'
/** 滑块通过后的重发：真机只把 tag 升到 bdr-cnt=1 并补两个重试头，URL 与 body 完全不变 */
const RETRY = 'bdr-cnt=1;n=0;s=-1;p=0'

/** 登录请求的入口标记；带 verify_ticket 说明是滑块通过后的重发 */
function entry (verifyTicket = '', extra: Record<string, string> = {}): Pick<Send, 'tag' | 'extra'> {
  if (!verifyTicket) return { tag: TAG, extra }
  return {
    tag: RETRY,
    extra: { 'x-tt-bdturing-retry': '1', 'x-tt-passport-replay-params': '{}', ...extra },
  }
}

export interface FlowOpts {
  auth: Auth
  dev: Dev
  ids: Ids
  mobile?: string
}

/** 登录链路中的一次待重放请求（2046 触发） */
interface Pending {
  path: string
  body: string
  data: LoginData
}

export class Login {
  readonly auth: Auth
  readonly dev: Dev
  readonly ids: Ids
  mobile: string
  mobileTicket = ''
  last?: Res
  lastData?: LoginData
  /** 最近一次发出的 form（滑块重试 / MFA 重放基底） */
  lastBody = ''
  lastPath = ''
  /** 2046 原请求；MFA 辅助请求会覆盖 last，所以单独留一份 */
  pending?: Pending

  /** 是否存在待重放的 2046 原请求 */
  get waiting (): boolean {
    return Boolean(this.pending)
  }

  constructor (opts: FlowOpts) {
    this.auth = opts.auth
    this.dev = opts.dev
    this.ids = opts.ids
    this.mobile = opts.mobile ? normalizeMobile(opts.mobile) : ''
  }

  ctx (): MfaCtx {
    return (this.pending?.data ?? this.lastData ?? {}) as MfaCtx
  }

  private async call (path: string, body: string | Buffer | null, extra: Partial<Send> = {}): Promise<LoginData> {
    const res = await send({ auth: this.auth, dev: this.dev, ids: this.ids, path, body, ...extra })
    this.last = res
    this.lastPath = path
    const data = parseData(res)
    this.lastData = data
    if (data.mobile_ticket) this.mobileTicket = String(data.mobile_ticket)
    if (typeof body === 'string') this.lastBody = body
    // 2046 留原始请求：后续验证请求不得覆盖，否则重放会变成重放验证接口
    if (Number(data.error_code) === 2046) {
      this.pending = { path, body: typeof body === 'string' ? body : '', data }
    }
    return data
  }

  /** 发送验证码（type=24；真机走 ttEncrypt+gzip，明文会被判旧客户端 1049） */
  sendCode (cred: CaptchaCredential = {}): Promise<LoginData> {
    return this.call('/passport/mobile/send_code/', buildSendCode(this.mobile, cred), { enc: 'tt', ...entry(cred.verifyTicket) })
  }

  /** 验证码登录；2046 表示进入二次验证 */
  smsLogin (code: string): Promise<LoginData> {
    return this.call('/passport/mobile/sms_login/', buildSmsLogin(code, this.mobileTicket, this.mobile), entry())
  }

  /** 密码登录；1105 滑块通过后带 cred 重发 */
  pwdLogin (password: string, ctx?: MfaCtx, cred: CaptchaCredential = {}): Promise<LoginData> {
    return this.call('/passport/user/login/', buildPwdLogin(this.mobile, password, { ctx, ...cred }), entry(cred.verifyTicket))
  }

  /** 密码二次验证（成功返回 ticket） */
  accountVerify (password: string): Promise<LoginData> {
    this.auth.verifiedWay = 'pwd_verify'
    return this.call('/passport/account/verify/', buildVerify(this.ctx(), password))
  }

  /** MFA 下发短信（type=22） */
  mfaSendCode (actType = '22', mobile11 = ''): Promise<LoginData> {
    return this.call('/passport/mobile/send_code/', buildMfaSendCode(actType, this.ctx(), mobile11), { enc: 'plain' })
  }

  /** MFA 提交验证码（actType 见 verify_ways[].act_type） */
  validateCode (code: string, actType = '22'): Promise<LoginData> {
    this.auth.verifiedWay = 'mobile_sms_verify'
    return this.call('/passport/mobile/validate_code/', buildValidateCode(code, actType, this.ctx()))
  }

  /** 上行短信验证：同一 body 轮询，手机发出短信后返回 registered=true */
  upSmsVerify (): Promise<LoginData> {
    this.auth.verifiedWay = 'mobile_up_sms_verify'
    return this.call('/passport/upsms/verify/', buildUpSmsVerify(this.ctx()))
  }

  /** MFA 扫码取码（scene=secondary_verify，与登录码不同） */
  mfaQrGetCode (service = QR_SERVICE): Promise<LoginData> {
    this.auth.verifiedWay = 'qr_code_verify'
    return this.call('/passport/mobile/get_qrcode/', buildMfaQrCodeBody(this.ctx(), service), { extra: { 'x-tt-app-id': String(this.dev.aid) } })
  }

  /** MFA 扫码轮询（new → confirmed） */
  mfaQrCheck (token: string): Promise<LoginData> {
    this.auth.verifiedWay = 'qr_code_verify'
    return this.call('/passport/mobile/validate_by_qrcode/', buildMfaQrCheckBody(token, this.ctx()), { extra: { 'x-tt-app-id': String(this.dev.aid) } })
  }

  /**
   * 重放触发 2046 的原请求：原 body + biz_params + std_verify_way，不带 verify_ticket。
   * 验证结果由轮换的 x-tt-passport-mfa-token 关联。
   */
  replayLogin (extra: Record<string, string> = {}): Promise<LoginData> {
    const base = this.pending
    if (base) {
      this.pending = undefined
      // 扫码登录必须用 check_qrconnect 专用表单；ctx 取原 2046 响应（lastData 已被验证响应覆盖）
      if (base.path.includes('check_qrconnect')) {
        this.lastData = base.data
        const p = new URLSearchParams(base.body)
        return this.qrReplay(p.get('token') ?? '', '', p.get('service') ?? QR_SERVICE, p.get('source') ?? 'pad')
      }
      const body = mergeBizParams(base.body, base.data as MfaCtx, {
        std_verify_way: this.auth.verifiedWay || 'mobile_sms_verify',
        ...extra,
      })
      return this.call(base.path, body)
    }
    // 1105 滑块兜底：复用最近一次请求重发
    if (!this.lastPath || !this.lastBody) throw new Error('没有待重放的请求')
    return this.call(this.lastPath, mergeBizParams(this.lastBody, {}, extra))
  }

  /** 登录成功后必调，否则 account/info 返回 13 */
  updateToken (): Promise<LoginData> {
    return this.call('/service/1/update_token/', buildUpdateToken(this.dev, this.ids, nowTime()))
  }

  accountInfo (): Promise<LoginData> {
    return this.call('/passport/account/info/v2/', null, { panel: 'normal' })
  }

  record (status: 1 | 2): Promise<LoginData> {
    return this.call('/passport/user/device_record_status/set/', buildDeviceRecordStatus(status))
  }

  /** 扫码三接口必须带完整设备身份：缺 device_id/x-tt-dt 的会话轮询几轮后被判 2156 兜底 */
  qrGetCode (service = QR_SERVICE, source = 'pad'): Promise<LoginData> {
    return this.call('/passport/mobile/get_qrcode/', buildQrCodeBody(service, source), {
      enc: 'plain',
      ...entry('', { 'x-tt-app-id': String(this.dev.aid) }),
    })
  }

  /** 真机 CheckQrConnect：POST，参数全在 query，载荷为空；service 不带 scheme */
  qrCheck (token: string, service = 'aweme.snssdk.com'): Promise<LoginData> {
    const body = buildQrCheckBody(token, service)
    return this.call('/passport/mobile/check_qrconnect/', body, {
      enc: 'plain',
      queryOnly: true,
      method: 'POST',
      ...entry('', { 'x-tt-app-id': String(this.dev.aid) }),
    })
  }

  qrReplay (token: string, verifyTicket = '', service = QR_SERVICE, source = 'pad'): Promise<LoginData> {
    return this.call(
      '/passport/mobile/check_qrconnect/',
      buildQrReplayBody(token, service, source, this.ctx(), verifyTicket, this.mobileTicket, this.auth.verifiedWay || 'mobile_sms_verify'),
      { enc: 'plain', ...entry(verifyTicket, { 'x-tt-app-id': String(this.dev.aid) }) },
    )
  }
}

function parseData (res: Res): LoginData {
  const env = (res.json ?? {}) as Envelope<LoginData>
  return { ...(env.data ?? {}) }
}
