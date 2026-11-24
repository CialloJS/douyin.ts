/** App 社交域：关系推荐、常看、附近的人与用户中心 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class Social {
  constructor (private readonly im: Im) {}

  /** 关注关系下的推荐 */
  spotlight (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/spotlight/relation/', { host: DOMAIN.social, query })
  }

  /** 熟人设置 */
  familiar (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/social/familiar/settings/', { host: DOMAIN.social, query })
  }

  /** 用户推荐（与好友域的 friend/recommend 是两个接口） */
  recommend (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v2/user/recommend', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 本地通讯录用户 */
  localUsers (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/local/user/list/', { host: DOMAIN.social, query })
  }

  /** 用户中心聚合数据 */
  center (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v2/user/center/get', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 用户中心计划 */
  centerPlan (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v2/user/center/plan', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 用户中心同步 */
  centerSync (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v2/user/center/sync', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 用户中心消息同步 */
  centerMsgs (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v2/user/center/sync/msgs', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 熟人视频访客列表 */
  visitors (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/familiar/video/visitor/list/', { host: DOMAIN.social, query })
  }

  /** 熟人视频统计上报 */
  videoStats (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/familiar/video/stats/', {
      host: DOMAIN.socialLf,
      enc: 'json',
      body,
    })
  }

  /** VoIP 冷启动拉取 */
  voipColdPull (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/janus/im/voip/cold_pull/v1/', { host: DOMAIN.social, query })
  }

  /** 收藏的用户列表 */
  collectUsers (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/collect/user/list/', { host: DOMAIN.platformM, query })
  }
}
