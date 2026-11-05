import { err } from '../error.js'
import { sniffImageFormat } from './image.js'
import { chunk, Vod } from './vod.js'
import { crc32Hex, Tos } from './tos.js'
import type { Http } from '../session/http.js'
import type { FileUploadAsset, ImageAsset, VideoAsset } from '../types.js'

/** commit 未回传像素尺寸时从图片头兜底解析 */
function imageSize (data: Uint8Array): { width: number; height: number } {
  const b = Buffer.from(data)
  if (b.length >= 24 && b.subarray(1, 4).toString() === 'PNG') {
    return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) }
  }
  if (b.length > 4 && b[0] === 0xff && b[1] === 0xd8) {
    let pos = 2
    while (pos + 9 < b.length) {
      if (b[pos] !== 0xff) { pos += 1; continue }
      const marker = b[pos + 1]!
      if (marker >= 0xc0 && marker <= 0xc3) {
        return { width: b.readUInt16BE(pos + 7), height: b.readUInt16BE(pos + 5) }
      }
      const size = b.readUInt16BE(pos + 2)
      if (size < 2) break
      pos += 2 + size
    }
  }
  if (b.length >= 10 && (b.subarray(0, 6).toString() === 'GIF87a' || b.subarray(0, 6).toString() === 'GIF89a')) {
    return { width: b.readUInt16LE(6), height: b.readUInt16LE(8) }
  }
  return { width: 0, height: 0 }
}

/** Cookie 鉴权 STS → 签名 VOD → TOS 上传工作流 */
export class Uploader {
  private readonly vod: Vod
  private readonly tos: Tos

  constructor (http: Http, userId: string) {
    this.vod = new Vod(http, userId)
    this.tos = new Tos(http, userId)
  }

  async uploadImage (data: Uint8Array): Promise<ImageAsset> {
    if (data.length === 0) err({ bytes: data.length })
    const format = sniffImageFormat(data)
    if (format === 'unknown') err({ format })
    const credentials = await this.vod.credentials()
    const address = await this.vod.apply(credentials, credentials.spaceName, 'image', data.length)
    await this.tos.put(address, data)
    const committed = await this.vod.commit(credentials, address.sessionKey, 'image', format)
    const size = imageSize(data)
    return {
      oid: committed.uri,
      skey: committed.secretKey,
      md5: committed.sourceMd5,
      dataSize: committed.imageSize ?? data.length,
      width: committed.imageWidth ?? size.width,
      height: committed.imageHeight ?? size.height,
      format,
    }
  }

  async uploadVideo (data: Uint8Array): Promise<VideoAsset> {
    if (data.length === 0) err({ bytes: data.length })
    const credentials = await this.vod.credentials()
    const address = await this.vod.apply(credentials, credentials.spaceName, 'video', data.length)
    const uploadId = await this.tos.init(address)
    const parts: string[] = []
    for (let offset = 0, part = 1; offset < data.length; offset += chunk, part += 1) {
      const piece = data.slice(offset, Math.min(offset + chunk, data.length))
      const crc = crc32Hex(piece)
      await this.tos.part(address, uploadId, part, crc, piece)
      parts.push(`${part}:${crc}`)
    }
    await this.tos.finish(address, uploadId, parts.join(','))
    const committed = await this.vod.commit(credentials, address.sessionKey, 'video')
    return { tkey: committed.uri, skey: committed.secretKey, md5: committed.sourceMd5 }
  }

  /** 文件上传（object 通道：public_file_config + GCM 服务端加密，≤10MiB） */
  async uploadFile (data: Uint8Array, name: string): Promise<FileUploadAsset> {
    if (!name.trim() || data.length === 0 || data.length > 10 * 1024 * 1024) {
      err({ name, bytes: data.length })
    }
    const credentials = await this.vod.credentials('public_file_config')
    const address = await this.vod.apply(credentials, credentials.spaceName, 'object', data.length)
    await this.tos.put(address, data)
    const committed = await this.vod.commit(credentials, address.sessionKey, 'object', undefined, address)
    return { uri: committed.uri, skey: committed.secretKey, md5: committed.sourceMd5, name, dataSize: data.length }
  }
}
