import { randomUUID } from 'node:crypto'
import { aidSign, normalizePassportPath, noonTs } from './sign/aid.js'
import { im, passport, web, UA } from './sign/const.js'
import { randomHex, randomTrace } from './sign/qs.js'
import { Jar } from './jar.js'
import { createLog } from './log.js'
import type { Log } from '../types.js'
import type { HttpOpts, Res, ResBytes } from './types.js'

/**
 * 抖音 HTTP 通道：Cookie/UA/超时封装 + Passport 请求头。
 * 签名（sign/qs/a_bogus）由调用方组装进 URL 后直发，本类不感知具体接口。
 */
export class Http {
  readonly jar: Jar
  readonly userId: string
  readonly ua: string
  readonly log: Log
  bizTraceId: string
  /** 服务端注册的桌面设备身份（登录时注入；'0' 表示未注册） */
  deviceId = '0'
  installId = '0'
  guid = randomHex(32)

  private readonly timeout: number
  private readonly portrait = `${randomUUID()}.login`

  constructor (opts: HttpOpts = {}) {
    // 时间参数交给 AbortSignal.timeout 原生校验，SDK 不重复判断
    this.timeout = opts.timeout ?? 30_000
    this.jar = new Jar(opts.cookie)
    this.userId = opts.userId ?? ''
    this.ua = opts.userAgent ?? UA
    this.log = opts.log ?? createLog({ tag: 'http' })
    // trace-id 首次生成后回写 jar：后续请求与 Passport 头必须同源
    this.bizTraceId = this.jar.get('biz_trace_id') ?? randomTrace()
    this.jar.set('biz_trace_id', this.bizTraceId)
  }

  /** 注入 device_register 签发的设备身份 */
  setDevice (device: { deviceId: string; installId: string; guid: string }): void {
    this.deviceId = device.deviceId
    this.installId = device.installId
    this.guid = device.guid
  }

  hasDevice (): boolean {
    return this.deviceId !== '0'
  }

  /** Passport 请求头；imdesktop（桌面，含登录）/ creator（web）分流 */
  passportHeaders (url?: string): Record<string, string> {
    // 登录与 IM 同走 imdesktop：desktop 判定优先，避免被 login 分支覆盖
    const desktop = Boolean(url?.startsWith(im.origin))
    const login = !desktop && Boolean(url?.startsWith(passport.origin))
    const headers: Record<string, string> = {
      Accept: 'application/json, text/javascript',
      Referer: desktop || login ? im.origin : `${web.origin}/creator-micro/home`,
    }
    const csrf = this.jar.get('passport_csrf_token') ?? this.jar.get('passport_csrf_token_default')
    if (csrf) headers['x-tt-passport-csrf-token'] = csrf
    headers['x-tt-passport-trace-id'] = this.bizTraceId
    headers['x-tt-passport-verify-portrait'] = this.portrait
    const domain = login ? 'passport' : desktop ? 'im' : 'web'
    const sign = this.aidSignFor(url, domain)
    if (sign) headers['x-tt-passport-aid-sign'] = sign
    if (desktop || login) return headers
    const secsdk = this.jar.get('x-web-secsdk-uid')
    if (secsdk) headers['x-secsdk-csrf-token'] = `000100000001${secsdk.replace(/-/g, '')}`
    return headers
  }

  async request (url: string, init: RequestInit = {}): Promise<Res<string>> {
    const res = await this.send(url, init)
    const text = await res.text()
    return { ok: res.ok, status: res.status, headers: res.headers, data: text, text }
  }

  /** 只负责解码；状态与业务失败由调用方按原始响应决定如何交回 */
  async json<T> (url: string, init: RequestInit = {}): Promise<Res<T>> {
    const res = await this.request(url, init)
    return { ...res, data: JSON.parse(res.text) as T }
  }

  async bytes (url: string, init: RequestInit = {}): Promise<ResBytes> {
    const res = await this.send(url, init)
    return { ok: res.ok, status: res.status, headers: res.headers, data: new Uint8Array(await res.arrayBuffer()) }
  }

  get (url: string, init: RequestInit = {}): Promise<Res<string>> {
    return this.request(url, { ...init, method: 'GET' })
  }

  /** Passport form 链路：body 已是 urlencoded 串，默认补 Content-Type */
  post (url: string, body = '', init: RequestInit = {}): Promise<Res<string>> {
    const headers = new Headers(init.headers)
    if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/x-www-form-urlencoded')
    return this.request(url, { ...init, headers, method: 'POST', body })
  }

  /** 媒体上传：body 原样透传，Content-Type 由调用方决定 */
  upload (url: string, body: NonNullable<RequestInit['body']>, init: RequestInit = {}): Promise<Res<string>> {
    return this.request(url, { ...init, method: 'POST', body })
  }

  private aidSignFor (url: string | undefined, domain: 'passport' | 'im' | 'web'): string | undefined {
    if (!url) return undefined
    const scope = { passport, im, web }[domain]
    try {
      return aidSign({
        aid: scope.aid,
        appKey: scope.appKey,
        path: normalizePassportPath(new URL(url).pathname),
        ts: noonTs(),
      })
    } catch {
      // aid-sign 只是加分项，签名失败不阻断请求
      return undefined
    }
  }

  private async send (url: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers)
    // UA/Cookie 只作默认值：调用方显式传入（主站 passport 会话）优先
    if (!headers.has('User-Agent')) headers.set('User-Agent', this.ua)
    const cookie = this.jar.header()
    if (cookie && !headers.has('Cookie')) headers.set('Cookie', cookie)
    const res = await fetch(url, {
      ...init,
      headers,
      signal: init.signal ?? AbortSignal.timeout(this.timeout),
    })
    this.absorb(res.headers)
    return res
  }

  /** 吸收 Set-Cookie 与 msToken：会话跨请求自续 */
  private absorb (headers: Headers): void {
    for (const line of headers.getSetCookie()) this.jar.absorb(line)
    const ms = headers.get('x-ms-token')
    if (ms) this.jar.set('msToken', ms)
  }
}
