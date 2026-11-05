import { getGroupList } from '../chat/list.js'
import { getGroupMembers, setGroupName, addGroupMembers, removeGroupMembers, leaveGroup, createGroup } from '../chat/group.js'
import { getGroupJoinRequests, reviewGroupJoinRequest } from '../chat/request.js'
import { verifyShare } from '../chat/share.js'
import { chatIdOf, toAddress } from './address.js'
import { GroupJoinRequestStatus } from '../types.js'
import type { Bot } from './bot.js'
import type { ActionResult, CreateGroupOptions, GroupInfo, GroupJoinRequestInfo, GroupMemberInfo, GroupShareInput, GroupShareResult } from '../types.js'

export class Grp {
  constructor (private readonly bot: Bot) {}

  /** 分页参数：cursor 起始游标，count 单页条数；缺省自动翻页拉全量 */
  async list (options: { cursor?: number; count?: number } = {}): Promise<Array<GroupInfo & { chatId: string }>> {
    return (await getGroupList(this.bot.ctx().inbox, options)).map(g => ({ chatId: chatIdOf(g), ...g }))
  }

  async members (chatId: string): Promise<GroupMemberInfo[]> {
    const list = await getGroupMembers(this.bot.ctx().inbox, toAddress(chatId))
    this.bot.rememberNicks(list)
    return list
  }

  /** 群入群申请；省略 chatId 查全部群 */
  async requests (chatId?: string): Promise<GroupJoinRequestInfo[]> {
    const shortId = chatId ? toAddress(chatId).conversationShortId : undefined
    const list = await getGroupJoinRequests(this.bot.ctx().inbox, shortId ? { conversationShortId: shortId } : {})
    this.bot.rememberNicks(list.map(r => ({ uid: r.applicantUid, nickname: r.applicantNickname })))
    return list
  }

  approve (requestId: string): Promise<ActionResult & { request?: GroupJoinRequestInfo }> {
    return reviewGroupJoinRequest(this.bot.ctx().inbox, requestId, GroupJoinRequestStatus.APPROVED)
  }

  reject (requestId: string): Promise<ActionResult & { request?: GroupJoinRequestInfo }> {
    return reviewGroupJoinRequest(this.bot.ctx().inbox, requestId, GroupJoinRequestStatus.REJECTED)
  }

  rename (chatId: string, name: string): Promise<ActionResult> {
    return setGroupName(this.bot.ctx().inbox, toAddress(chatId), name)
  }

  /** 拉人入群（cmd=650，成功/失败名单在返回里回读） */
  addMembers (chatId: string, uids: string[]): Promise<ActionResult & { success?: string[]; failed?: string[] }> {
    return addGroupMembers(this.bot.ctx().inbox, toAddress(chatId), uids)
  }

  /** 移出群成员（cmd=651） */
  removeMembers (chatId: string, uids: string[]): Promise<ActionResult> {
    return removeGroupMembers(this.bot.ctx().inbox, toAddress(chatId), uids)
  }

  /** 退出群聊（cmd=652，响应为空 body） */
  leave (chatId: string): Promise<ActionResult> {
    return leaveGroup(this.bot.ctx().inbox, toAddress(chatId))
  }

  /** 创建群聊（cmd=609），返回会话（含 chatId） */
  async create (options: CreateGroupOptions): Promise<ActionResult & { group?: GroupInfo; chatId?: string }> {
    const result = await createGroup(this.bot.ctx().inbox, options)
    return result.group ? { ...result, chatId: chatIdOf(result.group) } : result
  }

  /** 群分享校验：用邀请链接换群邀请凭证（ticket 可直接填入 groupCard.ticket 发卡） */
  verifyShare (input: GroupShareInput): Promise<GroupShareResult> {
    return verifyShare(this.bot.ctx().http, input)
  }
}
