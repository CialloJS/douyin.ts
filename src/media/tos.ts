import { api } from '../session/codes.js'
import { PC_UA } from '../live/transport.js'
import { err } from '../error.js'
import { asRecord } from './json.js'
import { randomId } from './sign.js'
import type { Http } from '../session/http.js'
import type { UploadAddress } from './vod.js'

/** TOS 以 CRC32 校验对象/分片完整性，Content-CRC32 必须为 8 位小写 hex */
let crcTable: Uint32Array | undefined
function table (): Uint32Array {
  if (crcTable) return crcTable
  crcTable = new Uint32Array(256)
  for (let n = 0; n < 256; n += 1) {
    let c = n
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    crcTable[n] = c >>> 0
  }
  return crcTable
}

export function crc32Hex (data: Uint8Array): string {
  let crc = 0xffffffff
  const values = table()
  for (const byte of data) crc = values[(crc ^ byte) & 0xff]! ^ (crc >>> 8)
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0')
}

/** TOS 存储侧：对象直传与分片上传，鉴权头由 ApplyUpload 下发 */
export class Tos {
  constructor (
    private readonly http: Http,
    private readonly userId: string,
  ) { }

  async put (address: UploadAddress, data: Uint8Array): Promise<void> {
    const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}`, {
      method: 'POST',
      headers: {
        ...this.headers(address.authorization, crc32Hex(data)),
        ...(address.uploadHeaders ?? {}),
        ...(address.gcmMode ? {
          'X-Upload-Server-Gcm-Encryption-Mode': address.gcmMode,
          'X-Upload-Server-Gcm-Encryption-Key': address.encryptionKey ?? '',
        } : {}),
      },
      body: new Uint8Array(data),
    })
    const result = asRecord(JSON.parse(response.text))
    if (!response.ok || Number(result['code']) !== 2000) err(result)
  }

  async init (address: UploadAddress): Promise<string> {
    const boundary = `----WebKitFormBoundary${randomId(16)}`
    const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}?phase=init`, {
      method: 'POST',
      headers: { ...this.headers(address.authorization), 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      body: `--${boundary}--\r\n`,
    })
    const result = asRecord(JSON.parse(response.text))
    const uploadId = String(asRecord(result['data'])['uploadid'] ?? '')
    if (!response.ok || Number(result['code']) !== 2000 || !uploadId) err(result)
    return uploadId
  }

  async part (address: UploadAddress, uploadId: string, part: number, crc: string, data: Uint8Array): Promise<void> {
    const query = new URLSearchParams({ uploadid: uploadId, part_number: String(part), phase: 'transfer' })
    const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}?${query}`, {
      method: 'POST',
      headers: { ...this.headers(address.authorization, crc), 'Content-Disposition': 'attachment; filename="undefined"' },
      body: new Uint8Array(data),
    })
    const result = asRecord(JSON.parse(response.text))
    if (!response.ok || Number(result['code']) !== 2000) err(result)
  }

  async finish (address: UploadAddress, uploadId: string, manifest: string): Promise<void> {
    const query = new URLSearchParams({ phase: 'finish', uploadid: uploadId })
    const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}?${query}`, {
      method: 'POST',
      headers: { ...this.headers(address.authorization), 'Content-Type': 'text/plain;charset=UTF-8' },
      body: manifest,
    })
    const result = asRecord(JSON.parse(response.text))
    if (!response.ok || Number(result['code']) !== 2000) err(result)
  }

  private headers (authorization: string, crc?: string): Record<string, string> {
    const headers: Record<string, string> = {
      Authorization: authorization,
      'Content-Type': 'application/octet-stream',
      'X-Storage-U': this.userId,
      'User-Agent': PC_UA,
    }
    if (crc) headers['Content-CRC32'] = crc
    return headers
  }
}
