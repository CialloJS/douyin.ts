import { api, site } from '../session/codes.js'
import { fingerprintParams } from '../live/transport.js'
import { err } from '../error.js'
import type { Http } from '../session/http.js'
import type { AwemeDetail, EncryptedVideoUrl } from '../types.js'

/** maya batch_play_info：用消息视频的 tkey 换加密 CDN 地址（私信视频协议不直发播放地址） */
export async function getVideoUrl (http: Http, tkey: string): Promise<EncryptedVideoUrl> {
  if (!tkey.trim()) err({ tkey })
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  const res = await http.json<{
    data?: { play_infos?: Array<{ encrypted_url?: { main_url?: string; backup_url?: string; expire_time?: number } }> }
  }>(
    `${site.im}${api.playInfo}?${params}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Referer: site.im },
      body: JSON.stringify({ req_infos: [{ tos_key: tkey, type: 2 }], with_caption: true }),
    },
  )
  const url = res.data?.data?.play_infos?.[0]?.encrypted_url
  if (!url?.main_url) err(res.data)
  return {
    mainUrl: url.main_url,
    ...(url.backup_url ? { backupUrl: url.backup_url } : {}),
    ...(url.expire_time ? { expireTime: url.expire_time } : {}),
  }
}

/** multi/aweme/detail:按 awemeId 批量拉消息中的作品详情（视频/图文） */
export async function awemeDetail (
  http: Http,
  awemeIds: string[],
  options: { originType?: string; requestSource?: number; conversationShortId?: string } = {},
): Promise<AwemeDetail[]> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('aweme_ids', JSON.stringify(awemeIds))
  params.set('origin_type', options.originType ?? 'chat')
  params.set('request_source', String(options.requestSource ?? 3))
  if (options.conversationShortId) params.set('conversation_short_id', options.conversationShortId)
  const res = await http.json<{ aweme_details?: unknown[] }>(
    `${site.edge}${api.awemeDetail}?${params}`,
    { method: 'POST', headers: { Referer: site.referer, 'Content-Type': 'application/json' }, body: '{}' },
  )
  return (res.data?.aweme_details ?? []).map(awemeOf)
}

function urlsOf (v: unknown): string[] | undefined {
  const list = (v as { url_list?: unknown } | undefined)?.url_list
  if (!Array.isArray(list)) return undefined
  return list.filter((u): u is string => typeof u === 'string' && u !== '')
}

function awemeOf (raw: unknown): AwemeDetail {
  const r = raw as Record<string, unknown>
  const video = r['video'] as Record<string, unknown> | undefined
  const author = r['author'] as Record<string, unknown> | undefined
  const avatar = urlsOf(author?.['avatar_thumb'])?.[0]
  const playUrls = urlsOf(video?.['play_addr'])
  const coverUrls = urlsOf(video?.['cover'])
  return {
    awemeId: String(r['aweme_id'] ?? ''),
    ...(typeof r['desc'] === 'string' && r['desc'] ? { desc: r['desc'] } : {}),
    ...(r['create_time'] != null ? { createTime: Number(r['create_time']) } : {}),
    ...(playUrls ? { playUrls } : {}),
    ...(coverUrls ? { coverUrls } : {}),
    ...(author && (author['sec_uid'] || author['nickname'] || avatar)
      ? {
          author: {
            ...(typeof author['sec_uid'] === 'string' && author['sec_uid'] ? { secUid: author['sec_uid'] } : {}),
            ...(typeof author['nickname'] === 'string' && author['nickname'] ? { nickname: author['nickname'] } : {}),
            ...(avatar ? { avatar } : {}),
          },
        }
      : {}),
    raw: r,
  }
}
