import { stickerList, stickerCollect, emojiTrending, strategyConfig, privacyImage } from '../message/resource.js'
import type { Bot } from './bot.js'
import type { StickerCollectResult, StickerPage, StrategyConfig } from '../types.js'

export class Sticker {
  constructor (private readonly bot: Bot) {}

  /** 表情资源列表；scenes 缺省我的收藏，其他面板场景可自行传参探测 */
  list (options?: { scenes?: string; cursor?: number; limit?: number }): Promise<StickerPage> {
    return stickerList(this.bot.ctx().http, options)
  }

  /** 我的收藏表情（CUSTOM_STICKER_PAGE 面板） */
  favs (): Promise<StickerPage> {
    return stickerList(this.bot.ctx().http)
  }

  /** 动图/GIF 表情：收藏中带 animate 动图的贴纸 */
  async gifs (): Promise<StickerPage> {
    const page = await stickerList(this.bot.ctx().http)
    return { ...page, list: page.list.filter(s => s.animate) }
  }

  /** 收藏/取消收藏表情（remove=true 取消） */
  collect (ids: string[], options?: { remove?: boolean }): Promise<StickerCollectResult> {
    return stickerCollect(this.bot.ctx().http, ids, options)
  }

  /** 热门表情分页（cursor+count 翻页） */
  trending (options?: { cursor?: number; count?: number }): Promise<StickerPage> {
    return emojiTrending(this.bot.ctx().http, options)
  }

  /** app 能力开关（决策树 + 动效资源包配置） */
  strategy (scenes?: string[]): Promise<StrategyConfig> {
    return strategyConfig(this.bot.ctx().http, scenes)
  }

  /** 图源 uri 渲染为打码图（分享卡片脱敏用），返回 CDN 直链列表 */
  privacyImage (uri: string, options?: { format?: string; tpl?: string }): Promise<string[]> {
    return privacyImage(this.bot.ctx().http, uri, options)
  }
}
