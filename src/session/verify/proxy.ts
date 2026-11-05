/** 验证组件请求代理:登录域带 Cookie,验证中心域不带,防止登录态串到 zijieapi */
import { err } from '../../error.js'
import { host as domain, time } from '../login/codes.js'
import type { Http } from '../http.js'
import type { Raw } from './types.js'

/** 验证页代理允许访问的主机 */
const ALLOWED = new Set<string>([domain.im, domain.login, domain.verify, domain.vcs, domain.web])

/** 带账号 Cookie + Passport 头的登录域;验证中心域(zijieapi)不带 Cookie,避免混入登录态 */
const AUTH = new Set<string>([domain.im, domain.login, domain.web])

/** 服务端 5001/2040/2046 常伴随参数错误,输出轨迹才能定位是哪个 SDK 字段不对 */
const TRACE = /:5001|=5001|"5001"|\[5001\]|error_code["']?\s*[:=]\s*20(46|40)/

/** 页面可透传的头必须剔除跳转/凭据/长度类字段,否则浏览器与 Node 会自行改写或报错 */
const BLOCKED = new Set([
  'connection',
  'content-length',
  'cookie',
  'host',
  'origin',
  'proxy-authorization',
  'referer',
  'set-cookie',
  'transfer-encoding',
])

export function allowHost (url: URL): void {
  if (ALLOWED.has(url.hostname.toLowerCase())) return
  err({ host: url.hostname })
}

export function cleanHeaders (headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(([key]) => !BLOCKED.has(key.toLowerCase())),
  )
}

export async function requestRaw (http: Http, url: string, init: RequestInit): Promise<Raw> {
  const hostname = new URL(url).hostname.toLowerCase()
  if (AUTH.has(hostname)) {
    const res = await http.request(url, {
      ...init,
      headers: { ...http.passportHeaders(url), ...(init.headers as Record<string, string> | undefined) },
    })
    trace(http, url, init, res.status, res.text)
    return { ok: res.ok, status: res.status, headers: res.headers, text: res.text }
  }
  const res = await fetch(url, {
    ...init,
    headers: { 'User-Agent': http.ua, ...(init.headers as Record<string, string> | undefined) },
    signal: AbortSignal.timeout(time.fetch),
  })
  const text = await res.text()
  trace(http, url, init, res.status, text)
  return { ok: res.ok, status: res.status, headers: res.headers, text }
}

function trace (http: Http, url: string, init: RequestInit, status: number, body: string): void {
  const text = body.slice(0, 300)
  if (status >= 200 && status < 300 && !TRACE.test(text)) return
  http.log.warn(`verify ${String(init.method ?? 'GET')} ${url} -> ${status} ${text}`)
}
