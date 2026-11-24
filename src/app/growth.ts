/** App 成长域：连续聊天、火焰成就与音频模型等增长类接口 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class Growth {
  constructor (private readonly im: Im) {}

  /** 连续聊天关系成就 */
  consecutive (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/growth/consecutive_chat/relation_achieve', {
      host: DOMAIN.social,
      query,
    })
  }

  /** 成长分享列表 */
  shareList (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/growth/share/list', {
      host: DOMAIN.social,
      enc: 'json',
      body,
    })
  }

  /** 连续聊天开关 */
  switch (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/growth/consecutive_switch/set/', {
      host: DOMAIN.socialLf,
      enc: 'json',
      body,
    })
  }

  /** 连续聊天上报 */
  report (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/consecutive_chat/report/', {
      host: DOMAIN.socialLf,
      enc: 'zstd-json',
      body,
    })
  }

  /** 动态策略 */
  dynamic (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/strategy/dynamic/', {
      host: DOMAIN.socialLf,
      enc: 'zstd-json',
      body,
    })
  }

  /** 语音识别模型配置 */
  audioModel (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/audio/model_config/', {
      host: DOMAIN.socialLf,
      query,
    })
  }

  /** 火焰成就 */
  flame (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im_communication/flame_achieve/get/', {
      host: DOMAIN.socialLf,
      query,
    })
  }
}
