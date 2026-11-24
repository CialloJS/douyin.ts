/** App 通知域：未读汇总与通知列表 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class Notice {
  constructor (private readonly im: Im) {}

  /** 各分类未读数 */
  count (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/notice/count/', { host: DOMAIN.social, query })
  }

  /** 通知列表 */
  list (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/notice/multi/', { host: DOMAIN.social, query })
  }
}
