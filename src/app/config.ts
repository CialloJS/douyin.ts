/** App IM 配置域：全局配置、策略、活跃状态与会话入口上报 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class Config {
  constructor (private readonly im: Im) {}

  /** 客户端 IM 配置 */
  base (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/config/', { host: DOMAIN.social, query })
  }

  /** 服务端全局配置 */
  global (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/service/config/global/', { host: DOMAIN.social, query })
  }

  /** 策略配置 */
  strategy (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/strategy/config/', { host: DOMAIN.social, query })
  }

  /** 重启降级配置 */
  reboot (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/reboot/misc/', { host: DOMAIN.social, query })
  }

  /** 用户活跃配置 */
  active (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/user/active/config/get', { host: DOMAIN.social, query })
  }

  /** 用户活跃心跳更新 */
  activeUpdate (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/user/active/update/', { host: DOMAIN.social, query })
  }

  /** 上报用户活跃状态（表单） */
  activeStatus (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/user/active/status/', {
      host: DOMAIN.social,
      enc: 'form',
      body,
    })
  }

  /** 进入会话上报 */
  enterChat (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/service/enter_chat/', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 进入消息 Tab 上报 */
  msgTabEnter (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/service/msg_tab/enter', {
      host: DOMAIN.social,
      enc: 'json',
      body,
    })
  }
}
