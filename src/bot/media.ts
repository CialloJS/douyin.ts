import { resolveMedia, fileNameOf } from '../media/source.js'
import { getVideoUrl, awemeDetail } from '../media/play.js'
import { getPeer } from '../media/peer.js'
import { getEmojiList } from '../message/emoji.js'
import type { Bot } from './bot.js'
import type {
  AwemeDetail, EmojiInfo, EncryptedVideoUrl, FileUploadAsset, GetPeerRequest, GetPeerResult,
  ImageAsset, MediaInput, VideoAsset,
} from '../types.js'

export class Media {
  constructor (private readonly bot: Bot) {}

  /** 图片上传：url/路径/base64/字节均可 */
  async image (input: MediaInput): Promise<ImageAsset> {
    return this.bot.ctx().uploader.uploadImage(await resolveMedia(input))
  }

  /** 视频上传：url/路径/base64/字节均可 */
  async video (input: MediaInput): Promise<VideoAsset> {
    return this.bot.ctx().uploader.uploadVideo(await resolveMedia(input))
  }

  /** 文件上传：名字缺省从来源推断 */
  async file (input: MediaInput, name?: string): Promise<FileUploadAsset> {
    return this.bot.ctx().uploader.uploadFile(await resolveMedia(input), name ?? fileNameOf(input))
  }

  /** 用消息视频的 tkey 换加密 CDN 播放地址（CENC 流，需解密后才能播放） */
  videoUrl (tkey: string): Promise<EncryptedVideoUrl> {
    return getVideoUrl(this.bot.ctx().http, tkey)
  }

  /** 按 awemeId 批量拉作品详情（视频/图文） */
  awemeDetail (
    awemeIds: string[],
    options?: { originType?: string; requestSource?: number; conversationShortId?: string },
  ): Promise<AwemeDetail[]> {
    return awemeDetail(this.bot.ctx().http, awemeIds, options)
  }

  /** CDN 传输节点调度（按文件信息选可用节点） */
  getPeer (req: GetPeerRequest): Promise<GetPeerResult> {
    return getPeer(this.bot.ctx().http, req)
  }

  /** 官方表情资源全量映射（id/键值/CDN 直链） */
  emojiList (): Promise<EmojiInfo[]> {
    return getEmojiList(this.bot.ctx().http)
  }
}
