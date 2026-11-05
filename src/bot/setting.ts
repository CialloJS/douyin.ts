import { desktopSetting, userSettings, complianceSetting } from '../notice/setting.js'
import type { Bot } from './bot.js'
import type { ComplianceSetting, DesktopSetting, UserSettings } from '../types.js'

export class Setting {
  constructor (private readonly bot: Bot) {}

  /** 桌面消息提醒设置 */
  desktop (): Promise<DesktopSetting> {
    return desktopSetting(this.bot.ctx().http)
  }

  /** 账号综合设置（私密等级/青少年模式，raw 透传全量字段） */
  account (): Promise<UserSettings> {
    return userSettings(this.bot.ctx().http)
  }

  /** 合规/青少年模式设置 */
  compliance (): Promise<ComplianceSetting> {
    return complianceSetting(this.bot.ctx().http)
  }
}
