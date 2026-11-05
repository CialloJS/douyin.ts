/** 自身资料：自动获取 uid 与昵称/头像，供登录收尾与 Bot 构造 */
import { im, mac } from '../session/sign/const.js'
import { api } from '../session/codes.js'
import type { Http } from '../session/http.js'
import type { SelfInfo } from '../types.js'

/** GET /aweme/v1/web/user/profile/self/ — 桌面 IM 自我资料（对齐 douyin-im getSelfProfile） */
export async function self (http: Http): Promise<SelfInfo> {
  const params = new URLSearchParams({
    aid: im.aid,
    version_name: im.version,
    version_code: im.version,
    device_platform: mac.platform,
    screen_width: mac.width,
    screen_height: mac.height,
    browser_language: 'zh-CN',
    browser_platform: mac.browserPlatform,
    browser_name: mac.browserName,
    browser_version: http.ua.replace(/^Mozilla\//, ''),
    browser_online: 'true',
    cookie_enabled: 'true',
    device_id: http.deviceId,
    did: http.deviceId,
    iid: http.installId,
    awemeim_guid: http.guid,
    channel: mac.channel,
  })
  const res = await http.json<Record<string, unknown>>(`${im.origin}${api.profileSelf}?${params}`)
  const user = (res.data['user'] ?? {}) as Record<string, unknown>
  const nickname = typeof user['nickname'] === 'string' ? user['nickname'] : undefined
  const uid = user['uid'] ?? user['user_id_str'] ?? user['user_id']
  // 对齐 douyin-im mapProfile：真实头像在 avatar_thumb.url_list
  const thumb = user['avatar_thumb'] as { url_list?: unknown } | undefined
  const avatar = Array.isArray(thumb?.url_list)
    ? thumb.url_list.find((url): url is string => typeof url === 'string' && url !== '')
    : undefined
  return {
    ...(uid != null ? { uid: String(uid) } : {}),
    ...(nickname ? { nickname } : {}),
    ...(avatar ? { avatar } : {}),
  }
}
