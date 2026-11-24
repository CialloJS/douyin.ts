/** App 资源域：表情、贴纸、收藏文件与好友相册 */
import { DOMAIN, rest } from './rest.js'
import type { Im } from './im.js'

type Query = Record<string, string | number>

export class Resource {
  constructor (private readonly im: Im) {}

  /** 资源位聚合（入口/面板配置） */
  resources (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/resources/list/aggregation/', { host: DOMAIN.social, query })
  }

  /** 表情资源 */
  emoji (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/resources/emoji/', { host: DOMAIN.normal3, query })
  }

  /** 表情搜索 */
  emoticon (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/resources/emoticon/search', { host: DOMAIN.socialLf, query })
  }

  /** 打招呼贴纸 */
  helloSticker (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/resources/hellosticker/', { host: DOMAIN.socialLf, query })
  }

  /** 收藏文件 */
  collectFile (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/collect_file/get', { host: DOMAIN.social, query })
  }

  /** 好友相册列表 */
  album (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/friend_album/media/get', { host: DOMAIN.social, query })
  }

  /** 批量加入好友相册 */
  albumAdd (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/friend_album/media/multi_add', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 上传通道配置（分片大小/域名，上传前先取） */
  uploadConfig (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/upload/config/v2', { host: DOMAIN.social, query })
  }
}
