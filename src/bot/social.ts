import { spotlight, familiarList, followUser, bubbleDetail } from '../contact/social.js'
import type { Bot } from './bot.js'
import type { Bubble, RelationPage, SocialUser } from '../types.js'

export class Social {
  constructor (private readonly bot: Bot) {}

  /** 关注/好友关系列表（count+source 可调） */
  spotlight (options?: { count?: number; source?: string }): Promise<RelationPage> {
    return spotlight(this.bot.ctx().http, options)
  }

  /** 可能认识的人 */
  familiar (options?: { count?: number; cursor?: number; recommendType?: number }): Promise<SocialUser[]> {
    return familiarList(this.bot.ctx().http, options)
  }

  /** 关注用户（响应体为空，只判 HTTP 状态） */
  follow (userId: string, secUid: string, options?: { type?: number; tag?: string }): Promise<void> {
    return followUser(this.bot.ctx().http, userId, secUid, options)
  }

  /** 气泡详情 */
  bubble (bubbleId: string, options?: { needCurrent?: boolean }): Promise<Bubble[]> {
    return bubbleDetail(this.bot.ctx().http, bubbleId, options)
  }
}
