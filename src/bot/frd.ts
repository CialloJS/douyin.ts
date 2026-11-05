import { getFriendList, getFriendRequests, reviewFriendRequest } from '../contact/friend.js'
import { chatIdOf } from './address.js'
import { FriendRequestStatus } from '../types.js'
import type { Bot } from './bot.js'
import type { ActionResult, FriendInfo, FriendRequestInfo } from '../types.js'

export class Frd {
  constructor (private readonly bot: Bot) {}

  /** 分页参数：cursor 起始游标，count 单页条数；缺省自动翻页拉全量 */
  async list (options: { cursor?: number; count?: number } = {}): Promise<Array<FriendInfo & { chatId: string }>> {
    const list = await getFriendList(this.bot.ctx().inbox, options)
    this.bot.rememberNicks(list)
    return list.map(f => ({ chatId: chatIdOf({ ...f, conversationType: 1 }), ...f }))
  }

  async requests (status?: FriendRequestStatus): Promise<FriendRequestInfo[]> {
    const list = await getFriendRequests(this.bot.ctx().inbox, status ? { status } : {})
    this.bot.rememberNicks(list.map(r => ({ uid: r.applicantUid, nickname: r.nickname })))
    return list
  }

  approve (uid: string): Promise<ActionResult> {
    return reviewFriendRequest(this.bot.ctx().inbox, uid, FriendRequestStatus.APPROVED)
  }

  reject (uid: string): Promise<ActionResult> {
    return reviewFriendRequest(this.bot.ctx().inbox, uid, FriendRequestStatus.REJECTED)
  }
}
