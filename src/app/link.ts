/** App Frontier 握手：URL 查询与请求头（X-Tt-Token 鉴权，独立于 web Cookie 通道） */
import { createHash } from 'node:crypto'
import { cmd } from '../session/codes.js'
import { ua } from './conf.js'
import type { Auth } from './auth.js'
import type { Dev, Ids } from './types.js'

/** WsUrlHelper 的默认地址：私有协议未开启时真机走这里 */
const ws = {
  host: 'wss://frontier-aweme.snssdk.com/ws/v2',
  fpid: '9',
} as const

/** ChannelInfo 的固定查询项；extra 在真机上被内联进 query */
const extra: Array<[string, string]> = [
  ['ne', '1'],
  ['ping-interval', '30'],
  ['ttnet_heartbeat_interval', '30'],
  ['is_background', '0'],
  ['ttnet_ignore_offline', '1'],
  ['ws_connect_protocol', '0'],
  ['qos_level', '2'],
]

/** access_key = md5(fpid + appKey + device_id + salt)，大小写不敏感但真机输出小写 */
export function wsUrl (dev: Dev, ids: Ids): string {
  const q = new URLSearchParams()
  q.set('fpid', ws.fpid)
  q.set('sdk_version', '2')
  q.set('platform', '0')
  q.set('version_code', String(dev.versionCode))
  q.set('aid', String(dev.aid))
  q.set('device_id', ids.device_id)
  q.set('iid', ids.iid)
  q.set('private_protocol_enable', 'false')
  q.set('transport_mode', '0')
  q.set('disable_fallback_websocket', 'false')
  for (const [k, v] of extra) q.set(k, v)
  q.set('access_key', createHash('md5').update(`${ws.fpid}${cmd.appKey}${ids.device_id}${cmd.salt}`).digest('hex'))
  return `${ws.host}?${q}`
}

/** 握手头：TTTokenManager 的 token 头 + IM 身份标识，缺 token 时服务端按未登录处理 */
export function wsHeaders (dev: Dev, auth: Auth): Record<string, string> {
  const h: Record<string, string> = {
    'User-Agent': ua(dev),
    'x-support-ack': '1',
  }
  const cookie = auth.cookie()
  if (cookie) h.Cookie = cookie
  const token = auth.tokens['x-tt-token']
  if (token) h['X-Tt-Token'] = token
  const supplement = auth.tokens['x-tt-token-supplement']
  if (supplement) h['X-Tt-Token-Supplement'] = supplement
  const uid = auth.jar.get('uid')
  if (uid) {
    h['x-tt-e-k'] = `${uid}+IM`
    h['x-tt-encrypt-debug'] = '1'
  }
  return h
}
