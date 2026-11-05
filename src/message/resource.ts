import { api, site, time } from '../session/codes.js'
import { fingerprintParams } from '../live/transport.js'
import { err } from '../error.js'
import type { Http } from '../session/http.js'
import type {
  Sticker,
  StickerCollectResult,
  StickerImage,
  StickerPage,
  StrategyConfig,
} from '../types.js'

/** 表情面板场景：我的收藏页；注意 aggregation 无浏览器签名会被服务端 blocked（emoticon/trending 才是登录态可用源） */
export const SCENES_FAVS = 'CUSTOM_STICKER_PAGE'

/**
 * 表情资源列表：/aweme/v1/web/im/resource/list/aggregation/，scenes 决定返回哪套贴纸。
 * 对应官方面板「收藏」「GIF」分区（浏览器实测收藏资源域 im-emoticon、s=im_123；GIF 为 s=im_124）。
 * 仅浏览器环境可用：无 a_bogus 签名时服务端返回文本 blocked（非 JSON），SDK 环境优先用 emojiTrending
 */
export async function stickerList (
  http: Http,
  options: { scenes?: string; cursor?: number; limit?: number } = {},
): Promise<StickerPage> {
  const scenes = options.scenes ?? SCENES_FAVS
  const params = new URLSearchParams({
    device_platform: 'webapp',
    aid: '1128',
    app_id: '1128',
    channel: 'channel_pc_web',
    scenes,
    source: scenes,
    custom_cursor: String(options.cursor ?? 0),
    custom_limit: String(options.limit ?? 50),
  })
  const res = await http.json<Record<string, unknown>>(
    `${site.web}${api.resourceList}?${params}`,
    { headers: { Referer: site.web } },
  )
  if (Number(res.data.status_code ?? 0) !== 0) return err(res.data)
  const bean = Object.values(res.data).find(isPageBean)
  if (!bean || !bean.resources) return { list: [], total: 0, cursor: 0, done: true }
  // 每个 resource 含 stickers 数组（官方 pc web 上 resource/sticker 两级）
  const stickers: Array<Record<string, unknown>> = []
  for (const r of bean.resources) {
    const rec = r as Record<string, unknown>
    if (Array.isArray(rec['stickers'])) stickers.push(...(rec['stickers'] as Array<Record<string, unknown>>))
  }
  return {
    list: stickers.map(stickerOf),
    total: Number(bean.total_counts ?? 0),
    cursor: Number(bean.next_cursor ?? 0),
    done: bean.is_completed === true,
  }
}

/** 收藏/取消收藏表情：/aweme/v1/web/im/resource/sticker/collect/，参数全部走 query，body 为固定 {} */
export async function stickerCollect (
  http: Http,
  ids: string[],
  options: { remove?: boolean; uri?: string; url?: string } = {},
): Promise<StickerCollectResult> {
  const params = new URLSearchParams({
    action: options.remove ? '1' : '0',
    sticker_ids: `[${ids.join(',')}]`,
    sticker_uri: options.uri ?? '',
    sticker_url: options.url ?? '',
    resource_id: '0',
    sticker_type: '0',
  })
  const res = await http.json<{ success_items?: Array<{ id_str?: string; id?: number }>; status_code?: number }>(
    `${site.web}${api.stickerCollect}?${params}`,
    { method: 'POST', headers: { Referer: site.web, 'Content-Type': 'application/json' }, body: '{}' },
  )
  if (Number(res.data.status_code ?? 0) !== 0) return err(res.data)
  return { ids: (res.data.success_items ?? []).map(s => s.id_str ?? String(s.id ?? '')) }
}

/**
 * emoticon/trending:热门表情分页（cursor+count 翻页，groupId 固定 1）。
 * 对应官方面板「贴纸」分区（官方互动贴纸，im-resource 域 s=im_111/im_2），是 lite_emoji 表情消息的推荐数据源
 */
export async function emojiTrending (
  http: Http,
  options: { cursor?: number; count?: number } = {},
): Promise<StickerPage> {
  const params = new URLSearchParams({
    cursor: String(options.cursor ?? 0),
    count: String(options.count ?? 50),
    groupId: '1',
  })
  const res = await http.json<{
    emoticon_data?: { has_more?: boolean; next_cursor?: number; stickers?: unknown[] }
  }>(
    `${site.web}${api.trending}?${params}`,
    { headers: { Referer: site.web } },
  )
  const data = res.data?.emoticon_data
  return {
    list: (data?.stickers ?? []).map(raw => stickerOf(raw as Record<string, unknown>)),
    total: 0, // 热门页无总量，done 用 has_more 表达
    cursor: Number(data?.next_cursor ?? 0),
    done: data?.has_more !== true,
  }
}

/** trending 短缓存：签名链接有效期极长（至 2027），缓存只为省去每次发表情都拉列表 */
let trendingCache: { at: number; page: StickerPage } | undefined

/**
 * 表情消息 URL 归一化：完整 URL 原样返回；否则视为 im-resource 资源 id，
 * 经 trending 匹配出带签名的 CDN 直链（签名时效长，缓存放大到 5 分钟）；列表未收录时退回无签名直链
 */
export async function stickerUrlOf (http: Http, emoji: string): Promise<string> {
  if (/^https?:\/\//.test(emoji)) return emoji
  if (!trendingCache || Date.now() - trendingCache.at > time.trending) {
    const page = await emojiTrending(http)
    trendingCache = { at: Date.now(), page }
  }
  for (const s of trendingCache.page.list) {
    const img = s.static ?? s.animate
    if (!img) continue
    if (img.uri.includes(emoji) || img.urls.some(u => u.includes(emoji))) return img.urls[0] ?? img.uri
  }
  return `${site.cdn}${emoji}`
}

/** strategy/config:app 能力开关（决策树 + 动效资源包配置） */
export async function strategyConfig (
  http: Http,
  scenes: string[] = ['interactive_resources'],
): Promise<StrategyConfig> {
  const params = new URLSearchParams({ app_id: '1128', scenes: JSON.stringify(scenes) })
  const res = await http.json<{
    decision_trees?: Record<string, unknown>
    interactive_resource_config?: Record<string, unknown>
  }>(
    `${site.web}${api.strategy}?${params}`,
    { headers: { Referer: site.web } },
  )
  return {
    ...(res.data?.decision_trees ? { decisionTrees: res.data.decision_trees } : {}),
    ...(res.data?.interactive_resource_config ? { interactiveResourceConfig: res.data.interactive_resource_config } : {}),
  }
}

/**
 * privacy/batch_build_image:把图源 uri 渲染为打码图(分享卡片脱敏头像/昵称场景),
 * desktop 指纹批 + JSON body,HAR 实证返回 pack_results[0].UrlList 直链列表
 */
export async function privacyImage (
  http: Http,
  uri: string,
  options: { format?: string; tpl?: string } = {},
): Promise<string[]> {
  const params = fingerprintParams(http.deviceId, http.guid)
  const body = JSON.stringify({
    convert_params: [{
      uri,
      format: options.format ?? 'tplv-x-get:large.image',
      tpl: options.tpl ?? '%s://%v/%v~%v',
    }],
  })
  const res = await http.json<{ data?: { pack_results?: Array<{ UrlList?: unknown[] }> } }>(
    `${site.web}${api.privacy}?${params}`,
    { method: 'POST', headers: { Referer: site.web, 'Content-Type': 'application/json' }, body },
  )
  const list = res.data?.data?.pack_results?.[0]?.UrlList
  if (!list) return err(res.data)
  return list.filter((u): u is string => typeof u === 'string')
}

function isPageBean (v: unknown): v is { resources?: unknown[]; total_counts?: unknown; next_cursor?: unknown; is_completed?: unknown } {
  return !!v && typeof v === 'object' && Array.isArray((v as { resources?: unknown }).resources)
}

function stickerOf (raw: Record<string, unknown>): Sticker {
  return {
    id: typeof raw['id_str'] === 'string' ? raw['id_str'] : String(raw['id'] ?? ''),
    type: Number(raw['sticker_type'] ?? 0),
    ...(typeof raw['display_name'] === 'string' && raw['display_name'] ? { name: raw['display_name'] } : {}),
    ...(typeof raw['hash'] === 'string' ? { hash: raw['hash'] } : {}),
    ...(typeof raw['sticker_info_source'] === 'string' ? { source: raw['sticker_info_source'] } : {}),
    ...(isImage(raw['static_url']) ? { static: imageOf(raw['static_url']) } : {}),
    ...(isImage(raw['animate_url']) ? { animate: imageOf(raw['animate_url']) } : {}),
  }
}

function isImage (v: unknown): v is { url_list?: unknown } {
  return !!v && typeof v === 'object' && Array.isArray((v as { url_list?: unknown }).url_list)
}

function imageOf (v: { url_list?: unknown }): StickerImage {
  return {
    width: Number((v as { width?: unknown }).width ?? 0),
    height: Number((v as { height?: unknown }).height ?? 0),
    uri: String((v as { uri?: unknown }).uri ?? ''),
    urls: (v.url_list as unknown[] | undefined)?.filter((u): u is string => typeof u === 'string') ?? [],
  }
}
