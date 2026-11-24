/** App 账号域：本人/他人主页、各类设置与社交计数 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class Account {
  constructor (private readonly im: Im) {}

  /** 本人主页：登录后拿 uid/sec_uid/昵称 */
  self (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/user/profile/self/', { host: DOMAIN.core, query })
  }

  /** 他人主页：sec_user_id 是唯一必填标识 */
  other (secUserId: string, query: Query = {}): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/user/profile/other/', {
      host: DOMAIN.core,
      query: { ...query, sec_user_id: secUserId },
    })
  }

  /** 主页场景配置（tab/入口等） */
  scene (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/user/profile/scene/', { host: DOMAIN.platform, query })
  }

  /** 个人设置 */
  userSettings (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/user/settings/', { host: DOMAIN.platform, query })
  }

  /** 全局设置 */
  settings (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/settings/', { host: DOMAIN.normal, query })
  }

  /** 社交关系设置 */
  socialSettings (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/social/settings/query/', { host: DOMAIN.platform, query })
  }

  /** 社交计数：真机 body 为 zstd 压缩的表单串 */
  socialCount (body: string): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/social/count/', {
      host: DOMAIN.platform,
      enc: 'zstd-form',
      body,
    })
  }

  /** 合规设置 */
  compliance (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/compliance/settings/', { host: DOMAIN.normal, query })
  }

  /** 封禁信息 */
  ban (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/punish/ban_info/', { host: DOMAIN.socialLf, query })
  }

  /** 紧急禁用状态 */
  forbid (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/punish/emergency_forbid_status/', { host: DOMAIN.socialLf, query })
  }

  /** DX 客户端状态 */
  dx (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/dx/app/status/', { host: DOMAIN.socialLf, query })
  }

  /** 资料同步提示（头像/昵称待更新红点） */
  syncTips (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/user/check/show_tips/sync_profile/', { host: DOMAIN.normalM, query })
  }

  /** 隐私图片（平台侧生成/查询） */
  privacyImage (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/privacy/build_privacy_image/', { host: DOMAIN.platform, query })
  }
}
