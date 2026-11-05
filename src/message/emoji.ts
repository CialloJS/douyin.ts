import { api, site, time } from '../session/codes.js'
import type { Http } from '../session/http.js'
import type { EmojiInfo } from '../types.js'

/**
 * 官方小表情全量映射（214 项），即官方表情面板「小表情」分区数据源。
 * 键值以文本形式收发（如消息里的 [微笑]），不做图片消息；tos-cn 域资源发 lite_emoji 会被服务端注入 s:visible 仅发送者可见
 */
export async function getEmojiList (http: Http): Promise<EmojiInfo[]> {
  const res = await http.json<{ emoji_list?: Array<{
    origin_uri?: string
    display_name?: string
    hide?: number
    emoji_url?: { uri?: string; url_list?: string[] }
  }> }>(`${site.web}${api.emojiList}`, {
    headers: { Referer: site.referer },
  })
  const list = res.data?.emoji_list ?? []
  return list.filter(e => !e.hide && e.display_name).map(e => ({
    id: (e.origin_uri ?? '').replace(/\.png$/, ''),
    name: e.display_name!,
    uri: e.emoji_url?.uri ?? '',
    urls: e.emoji_url?.url_list ?? [],
  }))
}

/** 小表情键值缓存：官方键值长期稳定，缓存只为省去每次发送都拉全量列表 */
let emojiCache: { at: number; map: Map<string, string> } | undefined

/** 小表情 id（如 weixiao）→ 显示键值（[微笑]）；未收录返回 undefined。命中后按官方文本形态发送 */
export async function emojiTextOf (http: Http, id: string): Promise<string | undefined> {
  if (!emojiCache || Date.now() - emojiCache.at > time.emoji) {
    const map = new Map((await getEmojiList(http)).map(e => [e.id, e.name]))
    emojiCache = { at: Date.now(), map }
  }
  return emojiCache.map.get(id)
}
