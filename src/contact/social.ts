import { api, site } from '../session/codes.js'
import { err } from '../error.js'
import { fingerprintParams } from '../live/transport.js'
import type { Http } from '../session/http.js'
import type { Bubble, RelationPage, SocialUser } from '../types.js'

/** bubble/detail_list：按 bubble_id 查气泡详情（need_user_current_bubble 附带当前使用标记） */
export async function bubbleDetail (
  http: Http,
  bubbleId: string,
  options: { needCurrent?: boolean } = {},
): Promise<Bubble[]> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('bubble_id', bubbleId)
  params.set('need_user_current_bubble', String(options.needCurrent ?? true))
  const res = await http.json<{ status_code?: number; bubble_list?: unknown[] }>(
    `${site.web}${api.bubble}?${params}`,
    { headers: { Referer: site.web } },
  )
  if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data)
  return (res.data?.bubble_list ?? []).map(bubbleOf)
}

/** spotlight/relation：关注/好友关系列表（默认 100 条，含推荐与真实网络标记） */
export async function spotlight (
  http: Http,
  options: { count?: number; source?: string } = {},
): Promise<RelationPage> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('count', String(options.count ?? 100))
  params.set('source', options.source ?? 'coldup_full')
  params.set('with_fstatus', '1')
  params.set('max_time', '0')
  params.set('min_time', '0')
  params.set('address_book_access', '1')
  params.set('new_user_login', '0')
  params.set('need_sorted_info', 'true')
  params.set('need_network_recommend', 'true')
  params.set('need_real_network', 'true')
  params.set('need_remove_share_panel', 'true')
  const res = await http.json<{
    status_code?: number
    followings?: unknown[]
    has_more?: boolean
    max_time?: number
    min_time?: number
  }>(
    `${site.web}${api.spotlight}?${params}`,
    { headers: { Referer: site.web } },
  )
  return {
    users: (res.data?.followings ?? []).map(socialOf),
    hasMore: res.data?.has_more === true,
    maxTime: Number(res.data?.max_time ?? 0),
    minTime: Number(res.data?.min_time ?? 0),
  }
}

/**
 * commit/follow/user：关注用户（type=0 关注；响应体为空，只能以 HTTP 状态判定）。
 * verifyFp 与设备绑定：verify_<deviceId>，缺设备时不下发
 */
export async function followUser (
  http: Http,
  userId: string,
  secUid: string,
  options: { type?: number; tag?: string } = {},
): Promise<void> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('user_id', userId)
  params.set('secUid', secUid)
  params.set('type', String(options.type ?? 0))
  params.set('tag', options.tag ?? 'frienddetail')
  if (http.hasDevice()) params.set('verifyFp', `verify_${http.deviceId}`)
  const res = await http.request(
    `${site.im}${api.follow}?${params}`,
    { method: 'POST', headers: { Referer: site.im } },
  )
  if (!res.ok) return err(res.data)
}

/** familiar/list：可能认识的人（version_code 特例 21.6.0，与常规版本不同） */
export async function familiarList (
  http: Http,
  options: { count?: number; cursor?: number; recommendType?: number } = {},
): Promise<SocialUser[]> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('version_code', '21.6.0')
  params.set('iid', http.installId)
  params.set('cursor', String(options.cursor ?? 0))
  params.set('vcd_count', '0')
  params.set('hotsoon_has_more', '0')
  params.set('only_total', '0')
  params.set('count', String(options.count ?? 100))
  params.set('order_by', '1')
  params.set('need_all_friend', '1')
  params.set('recommend_type', String(options.recommendType ?? 22))
  const res = await http.json<{ status_code?: number; user_list?: unknown[] }>(
    `${site.im}${api.familiar}?${params}`,
    { headers: { Referer: site.im } },
  )
  if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data)
  return (res.data?.user_list ?? []).map(socialOf)
}

function bubbleOf (raw: unknown): Bubble {
  const row = raw as Record<string, unknown>
  const resource = row['resource'] as Record<string, unknown> | undefined
  const light = urlsOf(resource?.['top_preview_light_url'])?.[0]
  const dark = urlsOf(resource?.['top_preview_dark_url'])?.[0]
  return {
    id: typeof row['bubble_id_str'] === 'string' ? row['bubble_id_str'] : String(row['bubble_id'] ?? ''),
    name: typeof row['bubble_name'] === 'string' ? row['bubble_name'] : '',
    type: Number(row['bubble_type'] ?? 0),
    source: Number(row['source'] ?? 0),
    ...(typeof row['description'] === 'string' && row['description'] ? { description: row['description'] } : {}),
    ...(light ? { lightPreview: light } : {}),
    ...(dark ? { darkPreview: dark } : {}),
    current: row['is_user_current_set'] === true,
    raw: row,
  }
}

function socialOf (raw: unknown): SocialUser {
  const row = raw as Record<string, unknown>
  const avatar = urlsOf(row['avatar_thumb'])?.[0] ?? urlsOf(row['avatar_small'])?.[0]
  return {
    uid: String(row['uid'] ?? ''),
    secUid: String(row['sec_uid'] ?? ''),
    nickname: typeof row['nickname'] === 'string' ? row['nickname'] : '',
    ...(avatar ? { avatar } : {}),
    ...(typeof row['signature'] === 'string' && row['signature'] ? { signature: row['signature'] } : {}),
    ...(typeof row['unique_id'] === 'string' && row['unique_id'] ? { uniqueId: row['unique_id'] } : {}),
    followStatus: Number(row['follow_status'] ?? 0),
    followerStatus: Number(row['follower_status'] ?? 0),
    raw: row,
  }
}

function urlsOf (value: unknown): string[] | undefined {
  const list = (value as { url_list?: unknown } | undefined)?.url_list
  if (!Array.isArray(list)) return undefined
  return list.filter((url): url is string => typeof url === 'string' && url !== '')
}
