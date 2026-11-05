/** webapp 批通道：环境参数 + 指纹 + a_bogus 签名，供网页侧读接口共用 */
import { aBogus } from './sign/bogus.js'
import { randomMsToken } from './sign/qs.js'
import { site } from './codes.js'
import type { Http } from './http.js'
import type { Res } from './types.js'

/** 抖音 PC 客户端 UA；a_bogus 计算用的 UA 必须与请求头一致，否则签名失效 */
export const WEB_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) douyin/8.7.0 Chrome/136.0.7103.59 Electron/36.4.0-rs.33.release.pgo.0 TTElectron/36.4.0-rs.33.release.pgo.0 Safari/537.36 awemePcClient/8.7.0 buildId/495279540 osName/Windows'

/** 与 WEB_UA 匹配的屏参；不传输，只参与本地 a_bogus 计算 */
const SCREEN = '1707|960|1707|1019|1707|960|1707|982|Windows'

/** webapp 批环境参数（HAR 实证；服务端不校验字段顺序） */
const envParams = (): Record<string, string> => ({
  device_platform: 'webapp',
  aid: '6383',
  channel: 'channel_pc_web',
  app_name: 'aweme',
  format: 'json',
  pc_client_type: '2',
  pc_libra_divert: 'Windows',
  update_version_code: '807000',
  support_h265: '1',
  support_dash: '1',
  version_code: '170400',
  version_name: '17.4.0',
  cookie_enabled: 'true',
  screen_width: '1707',
  screen_height: '960',
  browser_language: 'zh-CN',
  browser_platform: 'Win32',
  browser_name: 'Chrome',
  browser_version: '136.0.7103.59',
  browser_online: 'true',
  engine_name: 'Blink',
  engine_version: '136.0.7103.59',
  os_name: 'Windows',
  os_version: '10',
  cpu_core_num: '16',
  device_memory: '8',
  platform: 'PC',
  downlink: '7.15',
  effective_type: '4g',
  round_trip_time: '50',
})

/** webid 不在 Cookie：web_sign_token（JWT）payload.id 即 webid */
function webidOf (http: Http): string {
  const payload = http.jar.get('web_sign_token')?.split('.')[1]
  if (!payload) return ''
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { id?: unknown }
    return data.id ? String(data.id) : ''
  } catch {
    // 非标准 JWT：按未登录处理
    return ''
  }
}

/** 环境参数 + 指纹（verifyFp/fp 同源 s_v_web_id；uifid 用 UIFID） */
function fpParams (http: Http, extra: Record<string, string>): Record<string, string> {
  const verifyFp = http.jar.get('s_v_web_id')
  const params: Record<string, string> = { ...envParams(), ...extra }
  const webid = webidOf(http)
  const uifid = http.jar.get('UIFID')
  if (webid) params.webid = webid
  if (uifid) params.uifid = uifid
  if (verifyFp) {
    params.verifyFp = verifyFp
    params.fp = verifyFp
  }
  params.msToken = http.jar.get('msToken') ?? randomMsToken()
  return params
}

export interface WebOpts {
  params?: Record<string, string>
  origin?: string
}

/** 环境+指纹 query 直接作为 a_bogus 签名输入，签名结果再追加到 URL */
function signed (http: Http, path: string, opts: WebOpts, body: string): { url: string; headers: Record<string, string> } {
  const query = new URLSearchParams(fpParams(http, opts.params ?? {})).toString()
  const bogus = aBogus({ userAgent: WEB_UA, query, body, screenFingerprint: SCREEN })
  const origin = opts.origin ?? site.web
  return {
    url: `${origin}${path}?${query}&a_bogus=${encodeURIComponent(bogus)}`,
    headers: { 'User-Agent': WEB_UA, Referer: site.web },
  }
}

export function webGet<T> (http: Http, path: string, opts: WebOpts = {}): Promise<Res<T>> {
  const { url, headers } = signed(http, path, opts, '')
  return http.json<T>(url, { headers })
}

export function webPost<T> (
  http: Http,
  path: string,
  opts: WebOpts & { body?: Record<string, string> } = {},
): Promise<Res<T>> {
  const wire = new URLSearchParams(opts.body ?? {}).toString()
  const { url, headers } = signed(http, path, opts, wire)
  return http.json<T>(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: wire,
  })
}
