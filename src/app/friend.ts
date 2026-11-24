/** App 好友域：推荐、好友申请列表与审批 */
import { pbQuery } from './pb.js'
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'
import type { Dev, Ids } from './types.js'

type Query = Record<string, string | number>

export interface ApplyOpts {
  /** 0 待处理 / 1 已通过 / 2 已拒绝 */
  status?: number
  cursor?: string | number
  limit?: number
}

const PATH = {
  applies: '/v1/friend/get_receive_apply_list',
  reply: '/v1/friend/reply_apply',
}

export class Friend {
  constructor (
    private readonly im: Im,
    private readonly dev: Dev,
    private readonly ids: Ids,
  ) {}

  /** 可能认识的人 */
  recommend (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/user/friend/recommend/', { host: DOMAIN.social, query })
  }

  /** 推荐候选 topK */
  topk (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/user/friend/topk/', { host: DOMAIN.social, query })
  }

  /** 新推荐用户数量（红点） */
  recommendCount (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v2/new/recommend/user/count/', { host: DOMAIN.social, query })
  }

  /** 收到的好友申请（cmd=2048），游标由调用方翻页 */
  applies (opts: ApplyOpts = {}): Promise<Record<string, unknown>> {
    return pbQuery(this.im, this.dev, this.ids, PATH.applies, 2048, 'getFriendReceiveApplyList', {
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 100,
      getTotalCount: true,
      status: opts.status ?? 0,
    })
  }

  /** 审批好友申请（cmd=2049）：attitude 1 通过 / 2 拒绝 */
  reply (uids: Array<string | number>, attitude: 1 | 2): Promise<Record<string, unknown>> {
    return pbQuery(this.im, this.dev, this.ids, PATH.reply, 2049, 'replyFriendApply', {
      userId: uids,
      attitude,
      ext: {},
    })
  }
}
