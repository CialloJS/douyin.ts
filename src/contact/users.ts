import { api, site } from '../session/codes.js'
import { err } from '../error.js'
import { fingerprintParams } from '../live/transport.js'
import type { Http } from '../session/http.js'
import type { ProfileDetail, UserInfo, UserProfile } from '../types.js'

/** im/user/info：按 secUid 批量拉资料（昵称/头像/签名/关系，群昵称不随 605 下发只能在此查），50 一批 */
export async function userInfo (http: Http, secUids: string[]): Promise<UserInfo[]> {
  const result: UserInfo[] = []
  const list = [...new Set(secUids.filter(Boolean))]
  for (let offset = 0; offset < list.length; offset += 50) {
    const batch = list.slice(offset, offset + 50)
    const params = fingerprintParams(http.deviceId, http.guid)
    params.set('iid', http.installId)
    const form = new FormData()
    form.append('sec_user_ids', JSON.stringify(batch))
    const res = await http.json<{ status_code?: number; data?: Record<string, unknown>[] }>(
      `${site.im}${api.userInfo}?${params}`,
      { method: 'POST', body: form, headers: { Referer: site.im } },
    )
    if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data)
    for (const raw of res.data.data ?? []) {
      const item = infoOf(raw)
      if (item) result.push(item)
    }
  }
  return result
}

function infoOf (raw: Record<string, unknown>): UserInfo | undefined {
  const secUid = typeof raw['sec_uid'] === 'string' ? raw['sec_uid'] : ''
  if (!secUid) return undefined
  const avatar = avatarOf(raw['avatar_thumb'])
  return {
    uid: String(raw['uid'] ?? ''),
    secUid,
    ...(typeof raw['nickname'] === 'string' && raw['nickname'] ? { nickname: raw['nickname'] } : {}),
    ...(avatar ? { avatar } : {}),
    ...(typeof raw['signature'] === 'string' && raw['signature'] ? { signature: raw['signature'] } : {}),
    ...(typeof raw['short_id'] === 'string' && raw['short_id'] ? { shortId: raw['short_id'] } : {}),
    ...(typeof raw['unique_id'] === 'string' && raw['unique_id'] ? { uniqueId: raw['unique_id'] } : {}),
    ...(raw['follow_status'] != null ? { followStatus: Number(raw['follow_status']) } : {}),
    ...(raw['follower_status'] != null ? { followerStatus: Number(raw['follower_status']) } : {}),
    ...(typeof raw['is_block'] === 'boolean' ? { isBlock: raw['is_block'] } : {}),
    ...(raw['im_activeness'] != null ? { imActiveness: Number(raw['im_activeness']) } : {}),
    raw,
  }
}

/** 批量取昵称/头像，按 secUid 索引（内部补全群昵称、发送者昵称用） */
export async function getUserProfiles (http: Http, secUids: string[]): Promise<Map<string, UserProfile>> {
  const result = new Map<string, UserProfile>()
  for (const item of await userInfo(http, secUids)) {
    if (!item.nickname && !item.avatar) continue
    result.set(item.secUid, {
      ...(item.nickname ? { nickname: item.nickname } : {}),
      ...(item.avatar ? { avatar: item.avatar } : {}),
    })
  }
  return result
}

/** profile/scene：对话场景资料（响应顶层即用户对象，字段比 profile/other 少） */
export async function profileScene (http: Http, secUid: string): Promise<ProfileDetail> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('sec_user_id', secUid)
  params.set('wish_flag', '1')
  params.set('scene', '5')
  params.set('source', '4')
  const res = await http.json<Record<string, unknown>>(
    `${site.edge}${api.profileScene}?${params}`,
    { headers: { Referer: site.referer } },
  )
  return profileOf(res.data)
}

/** profile/other：完整资料（user 字段打包，含地域/年龄等原始字段） */
export async function profileOther (http: Http, secUid: string): Promise<ProfileDetail> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('source', 'channel_pc_web')
  params.set('sec_user_id', secUid)
  params.set('personal_center_strategy', '1')
  params.set('profile_other_record_enable', '1')
  params.set('land_to', '1')
  const res = await http.json<{ user: Record<string, unknown> }>(
    `${site.edge}${api.profileOther}?${params}`,
    { headers: { Referer: site.referer } },
  )
  return profileOf(res.data.user)
}

/** profile/self：自己的完整资料（响应顶层 user 字段；imdesktop 版无 status_code，以 user 是否出现为准） */
export async function profileSelf (http: Http): Promise<ProfileDetail> {
  const params = fingerprintParams(http.deviceId, http.guid)
  const res = await http.json<{ user: Record<string, unknown> }>(
    `${site.im}${api.profileSelf}?${params}`,
    { headers: { Referer: site.referer } },
  )
  return profileOf(res.data.user)
}

function profileOf (raw: Record<string, unknown>): ProfileDetail {
  // self 用 avatar_larger/avatar_168x168，other/scene 用 avatar_thumb，多字段兜底
  const avatar =
    avatarOf(raw['avatar_thumb']) ??
    avatarOf(raw['avatar_larger']) ??
    avatarOf(raw['avatar_168x168'])
  return {
    uid: String(raw['uid'] ?? ''),
    secUid: String(raw['sec_uid'] ?? ''),
    ...(typeof raw['nickname'] === 'string' && raw['nickname'] ? { nickname: raw['nickname'] } : {}),
    ...(typeof raw['signature'] === 'string' && raw['signature'] ? { signature: raw['signature'] } : {}),
    ...(avatar ? { avatar } : {}),
    ...(typeof raw['unique_id'] === 'string' && raw['unique_id'] ? { uniqueId: raw['unique_id'] } : {}),
    ...(raw['following_count'] != null ? { followingCount: Number(raw['following_count']) } : {}),
    ...(raw['follower_count'] != null ? { followerCount: Number(raw['follower_count']) } : {}),
    ...(raw['follow_status'] != null ? { followStatus: Number(raw['follow_status']) } : {}),
    ...(raw['follower_status'] != null ? { followerStatus: Number(raw['follower_status']) } : {}),
    raw,
  }
}

function avatarOf (value: unknown): string | undefined {
  const list = (value as { url_list?: unknown } | undefined)?.url_list
  if (!Array.isArray(list)) return undefined
  return list.find((url): url is string => typeof url === 'string' && url !== '')
}
