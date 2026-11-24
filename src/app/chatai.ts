/** App 聊天智能域：Gaga、宠物精灵与子弹事件 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class ChatAi {
  constructor (private readonly im: Im) {}

  /** Gaga 聚合信息 */
  gaga (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/chatai/gagas/aggr_info', {
      host: DOMAIN.social,
      enc: 'json',
      body,
    })
  }

  /** 宠物聚合信息 */
  pet (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/chatai/pet/aggr_info/', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 宠物精灵邀请卡 */
  petCard (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/pet_elf/invite_card/get/', {
      host: DOMAIN.socialLf,
      query,
    })
  }

  /** 子弹事件请求并更新 */
  bullet (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/bullet/common_event/request_and_update', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 子弹事件数据提交 */
  bulletSubmit (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/bullet/common_event/submit_data', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }
}
