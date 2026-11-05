import { noticeCount, noticeList } from '../notice/notify.js'
import type { Bot } from './bot.js'
import type { NoticeCount, NoticePage } from '../types.js'

export class Notice {
  constructor (private readonly bot: Bot) {}

  /** 通知分组未读数（红点轮询用） */
  count (): Promise<NoticeCount[]> {
    return noticeCount(this.bot.ctx().http)
  }

  /** 通知列表（缺省互动分组 401；markRead=false 拉取不标记已读） */
  list (options?: { count?: number; group?: number; maxTime?: number; minTime?: number; markRead?: boolean }): Promise<NoticePage> {
    return noticeList(this.bot.ctx().http, options)
  }
}
