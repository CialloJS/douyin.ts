import { danmaku, playProgress, seriesRecord, mixRecord, historyWrite, safetyCheck } from '../media/watch.js'
import type { Bot } from './bot.js'
import type { Danmaku } from '../types.js'

export class Watch {
  constructor (private readonly bot: Bot) {}

  /** 拉取作品弹幕（startTime/endTime 毫秒偏移窗口） */
  danmaku (
    itemId: string,
    options?: { groupId?: string; startTime?: number; endTime?: number; duration?: number; token?: string },
  ): Promise<Danmaku[]> {
    return danmaku(this.bot.ctx().http, itemId, options)
  }

  /** 上报播放进度 */
  progress (itemId: string, progress: number, duration: number): Promise<void> {
    return playProgress(this.bot.ctx().http, itemId, progress, duration)
  }

  /** 短剧剧集观看记录 */
  series (seriesId: string, itemId: string, episode: number): Promise<void> {
    return seriesRecord(this.bot.ctx().http, seriesId, itemId, episode)
  }

  /** 合集观看记录 */
  mix (mixId: string, itemId: string, episode: number): Promise<void> {
    return mixRecord(this.bot.ctx().http, mixId, itemId, episode)
  }

  /** 写入观看历史 */
  history (awemeId: string, options?: { authorId?: string; preItemId?: string }): Promise<void> {
    return historyWrite(this.bot.ctx().http, awemeId, options)
  }

  /** 批量查作品安全等级 */
  safety (itemIds: string[]): Promise<Array<Record<string, unknown>>> {
    return safetyCheck(this.bot.ctx().http, itemIds)
  }
}
