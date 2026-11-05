import { self } from '../contact/self.js'
import { accountInfo, beatToken } from '../contact/account.js'
import { userInfo, profileScene, profileOther, profileSelf } from '../contact/users.js'
import { onlineStatus, heartbeat, activeSwitch } from '../live/active.js'
import type { Bot } from './bot.js'
import type { AccountInfo, OnlineItem, ProfileDetail, SelfInfo, UserInfo } from '../types.js'

export class User {
  constructor (private readonly bot: Bot) {}

  self (): Promise<SelfInfo> {
    return self(this.bot.http())
  }

  /** passport 账号详情（uid/昵称/手机/邮箱，登录态） */
  account (): Promise<AccountInfo> {
    return accountInfo(this.bot.http())
  }

  /** passport 令牌心跳（scene=boot 启动 / polling 周期轮询），续杯防掉线 */
  beatToken (scene = 'boot'): Promise<void> {
    return beatToken(this.bot.http(), scene)
  }

  /** 批量查用户信息（昵称/头像/签名/关系），按 secUid */
  info (secUids: string[]): Promise<UserInfo[]> {
    return userInfo(this.bot.http(), secUids)
  }

  /** 对话场景资料（字段比 profileOther 少） */
  profileScene (secUid: string): Promise<ProfileDetail> {
    return profileScene(this.bot.http(), secUid)
  }

  /** 完整资料（含地域/年龄等原始字段，raw 透传） */
  profileOther (secUid: string): Promise<ProfileDetail> {
    return profileOther(this.bot.http(), secUid)
  }

  /** 自己的完整资料 */
  profileSelf (): Promise<ProfileDetail> {
    return profileSelf(this.bot.http())
  }

  /** 批量查 sec 用户在线状态 */
  onlineStatus (secUserIds: string[], source?: string): Promise<OnlineItem[]> {
    return onlineStatus(this.bot.http(), secUserIds, source)
  }

  /** im 活跃心跳上报（登录后打一次即可） */
  heartbeat (): Promise<void> {
    return heartbeat(this.bot.http())
  }

  /** 在线状态开关（1=开启，我可被对方看到在线） */
  activeSwitch (): Promise<number> {
    return activeSwitch(this.bot.http())
  }
}
