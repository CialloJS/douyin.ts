/** App 群域：群列表、指标、活跃信息、群资料与可见范围 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class Group {
  constructor (private readonly im: Im) {}

  /** 我加入的群列表 */
  groups (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/list/self/', { host: DOMAIN.social, query })
  }

  /** 群指标（周期维度） */
  indicators (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/get_group_indicators', {
      host: DOMAIN.social,
      enc: 'json',
      body,
    })
  }

  /** 区间内群聊链条 */
  chains (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/group_chains_by_range/get', {
      host: DOMAIN.social,
      enc: 'form',
      body,
    })
  }

  /** 按群 id 取链条（与区间版同形，参数换成 group_id） */
  chain (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/group_chains_by_id/get', {
      host: DOMAIN.social,
      enc: 'form',
      body,
    })
  }

  /** 群打卡信息 */
  checkin (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/interest/checkin/conversation/info/get', {
      host: DOMAIN.platform,
      enc: 'form',
      body,
    })
  }

  /** 群打卡权限校验 */
  checkinAuth (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/interest/checkin/conversation/auth/check', {
      host: DOMAIN.platform,
      enc: 'form',
      body,
    })
  }

  /** 成员设置更新 */
  memberSettings (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/member_settings/update', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 群操作扫描 */
  scan (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/operation/scan', { host: DOMAIN.social, query })
  }

  /** 群标签扫描 */
  tags (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/tag/scan', { host: DOMAIN.social, query })
  }

  /** 群活跃信息 */
  active (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/active_info/get', {
      host: DOMAIN.social,
      enc: 'zstd-form',
      body,
    })
  }

  /** 群活跃信息扫描 */
  activeScan (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/active_info/scan', { host: DOMAIN.social, query })
  }

  /** 群号 */
  number (shortId: string | number): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/get_group_number/', {
      host: DOMAIN.social,
      enc: 'form',
      body: { conversation_short_id: String(shortId) },
    })
  }

  /** 群资料更新 */
  updateGroup (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/update', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 设置用户的群可见列表 */
  visible (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/set_user_group_list/', {
      host: DOMAIN.social,
      enc: 'form',
      body,
    })
  }

  /** 群合照样式 */
  mixPhoto (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/mix_photo_style/get', { host: DOMAIN.social, query })
  }

  /** 群资料校验 */
  validate (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/validate_info', { host: DOMAIN.social, query })
  }

  /** 群升级信息 */
  upgrade (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/upgrade_info', { host: DOMAIN.social, query })
  }

  /** 群升级信息列表 */
  upgrades (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/upgrade_info_list/', { host: DOMAIN.social, query })
  }

  /** 推荐折叠群 */
  foldGroups (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/recom_fold_groups', { host: DOMAIN.social, query })
  }

  /** 群任务列表 */
  tasks (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/group_task/list', { host: DOMAIN.social, query })
  }

  /** 群任务更新 */
  taskUpdate (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/group_task/update', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 群操作批量校验 */
  multiCheck (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group_v2/action/multi_check', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 入群门槛设置 */
  entryLimit (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/settings/entry_limit/', { host: DOMAIN.social, query })
  }

  /** 群聊词库设置 */
  words (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/group/settings/words/', { host: DOMAIN.social, query })
  }
}
