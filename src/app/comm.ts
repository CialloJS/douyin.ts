/** App 通信域：实验命中、合并消息卡与杂项上报 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

export class Comm {
  constructor (private readonly im: Im) {}

  /** 实验命中查询 */
  expHit (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/exp_hit/query/', {
      host: DOMAIN.social,
      enc: 'json',
      body,
    })
  }

  /** 合并消息卡准备 */
  mergePrepare (body: Record<string, unknown> | string): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/merge_msg_card/prepare/', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 杂项上报 */
  misc (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/misc/', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 分享上报 */
  shareReport (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/share_report/', {
      host: DOMAIN.social,
      enc: 'json',
      body,
    })
  }
}
