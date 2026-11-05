import { api, site } from '../session/codes.js'
import { fingerprintParams } from '../live/transport.js'
import { err } from '../error.js'
import type { Http } from '../session/http.js'
import type { Notice, NoticeCount, NoticePage } from '../types.js'

/** notice/count：各通知分组未读数（登录后轮询红点用） */
export async function noticeCount (http: Http): Promise<NoticeCount[]> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('is_new_notice', '1')
  params.set('need_social_count', '1')
  const res = await http.json<{ status_code?: number; notice_count?: unknown[] }>(
    `${site.im}${api.noticeCount}?${params}`,
    { headers: { Referer: site.im } },
  )
  if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data)
  return (res.data?.notice_count ?? []).map(countOf)
}

/** notice/：通知列表（缺省互动分组 401；isMarkRead 默认拉取即标记已读，响应体 v2 优先） */
export async function noticeList (
  http: Http,
  options: { count?: number; group?: number; maxTime?: number; minTime?: number; markRead?: boolean } = {},
): Promise<NoticePage> {
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  params.set('address_book_access', '1')
  params.set('appTheme', 'light')
  params.set('count', String(options.count ?? 20))
  params.set('gps_access', '0')
  params.set('is_mark_read', options.markRead === false ? '0' : '1')
  params.set('is_new_notice', '1')
  params.set('max_time', String(options.maxTime ?? 0))
  params.set('min_time', String(options.minTime ?? 1))
  params.set('notice_group', String(options.group ?? 401))
  params.set('top_group', '0')
  params.set('user_avatar_shrink', '144_144')
  params.set('video_cover_shrink', '192_192')
  const res = await http.json<{
    status_code?: number
    notice_list?: unknown[]
    notice_list_v2?: unknown[]
    has_more?: number | boolean
    max_time?: number
    min_time?: number
  }>(
    `${site.im}${api.notice}?${params}`,
    { headers: { Referer: site.im } },
  )
  if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data)
  const v2 = res.data?.notice_list_v2 ?? []
  return {
    list: (v2.length > 0 ? v2 : res.data?.notice_list ?? []).map(noticeOf),
    hasMore: Number(res.data?.has_more ?? 0) === 1 || res.data?.has_more === true,
    maxTime: Number(res.data?.max_time ?? 0),
    minTime: Number(res.data?.min_time ?? 0),
  }
}

function countOf (raw: unknown): NoticeCount {
  const r = raw as Record<string, unknown>
  return {
    group: Number(r['group'] ?? 0),
    count: Number(r['count'] ?? 0),
    dotCount: Number(r['dot_count'] ?? 0),
    latestTime: Number(r['latest_time'] ?? 0),
    showType: Number(r['show_type'] ?? 0),
    interactiveShowType: Number(r['interactive_show_type'] ?? 0),
  }
}

function noticeOf (raw: unknown): Notice {
  const r = raw as Record<string, unknown>
  return {
    nid: String(r['nid'] ?? ''),
    type: Number(r['type'] ?? 0),
    createTime: Number(r['create_time'] ?? 0),
    raw: r,
  }
}
