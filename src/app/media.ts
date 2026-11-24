/** App 发送前媒体归一化：cookie 通道上传输入源，产出资产供 wire 组装 */
import { Uploader } from '../media/upload.js'
import { fileNameOf, isInput, resolveMedia } from '../media/source.js'
import { extractVideoPoster, probeVideo } from '../media/video.js'
import { Http } from '../session/http.js'
import type { MsgBody } from '../types.js'
import type { Auth } from './auth.js'
import type { Im } from './im.js'

export class Media {
  constructor (private readonly im: Im, private readonly auth: Auth) {}

  /** App 网关不代传媒体；上传链路复用登录 cookie，每次取最新会话避免 token 轮换后失效 */
  async prepare (body: MsgBody): Promise<MsgBody> {
    if (body.type !== 'image' && body.type !== 'video' && body.type !== 'file') return body
    const uid = await this.im.uid()
    const up = new Uploader(new Http({ cookie: this.auth.cookie(), userId: uid }), uid)
    if (body.type === 'image') {
      if (!isInput(body.image)) return body
      return { ...body, image: await up.uploadImage(await resolveMedia(body.image)) }
    }
    if (body.type === 'file') {
      const file = body.file
      if (!('source' in file)) return body
      return {
        ...body,
        file: { asset: await up.uploadFile(await resolveMedia(file.source), file.name ?? fileNameOf(file.source)) },
      }
    }
    const video = body.video
    if (!('source' in video)) return body
    const bytes = await resolveMedia(video.source)
    const dims = await probeVideo(bytes)
    let width = video.width ?? dims.width
    let height = video.height ?? dims.height
    let poster = video.poster
    if (poster === undefined) {
      const shot = await extractVideoPoster(bytes)
      poster = await up.uploadImage(shot.jpeg)
      width ||= shot.width
      height ||= shot.height
    } else if (isInput(poster)) {
      poster = await up.uploadImage(await resolveMedia(poster))
    }
    return {
      ...body,
      video: { asset: await up.uploadVideo(bytes), poster, width, height },
    }
  }
}
