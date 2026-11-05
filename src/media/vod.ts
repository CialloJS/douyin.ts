import { randomBytes } from 'node:crypto'
import { api, site, vod } from '../session/codes.js'
import { PC_UA, fingerprintParams } from '../live/transport.js'
import { err } from '../error.js'
import { asRecord } from './json.js'
import { randomId, signVodRequest } from './sign.js'
import type { Http } from '../session/http.js'
import type { ImageFormat, UploadCredentials } from '../types.js'

/** 分片上传单段大小，需与 ApplyUpload 声明的 FileSize 协商一致 */
export const chunk = vod.part

export interface UploadAddress {
  storeUri: string
  authorization: string
  host: string
  sessionKey: string
  /** object（文件）上传的额外节点头 */
  uploadHeaders?: Record<string, string>
  /** object 上传 GCM 加密参数（服务端加密模式） */
  gcmMode?: string
  encryptionKey?: string
}

interface UploadProcessFunction {
  name: 'Encryption'
  input: {
    Config: Record<string, string>
    PolicyParams: Record<string, string>
  }
}

export interface CommittedUpload {
  uri: string
  secretKey: string
  sourceMd5: string
  imageSize?: number
  imageWidth?: number
  imageHeight?: number
}

type FileType = 'image' | 'video' | 'object'

type Process = (format?: ImageFormat) => UploadProcessFunction[]

/** 提交阶段按文件类型下发转码/加密策略；object 走 TOS 服务端 GCM，无需 process */
const processes: Record<FileType, Process> = {
  object: () => [],
  video: () => [{
    name: 'Encryption',
    input: {
      Config: { copies: 'cipher_v2', aes_chunk_size: '524288' },
      PolicyParams: { 'policy-set': 'medium' },
    },
  }],
  image: (format) => {
    const policy: Record<string, string> = format === 'gif'
      ? { 'policy-set': 'still', 'still-width': '480', 'still-height': '480' }
      : { 'policy-set': 'check,thumb,medium,large' }
    return [{ name: 'Encryption', input: { Config: { copies: 'cipher_v2' }, PolicyParams: policy } }]
  },
}

export function uploadProcessFunctions (fileType: FileType, imageFormat?: ImageFormat): UploadProcessFunction[] {
  return processes[fileType](imageFormat)
}

/** Cookie 鉴权 STS → 签名 VOD → TOS 上传工作流中的 VOD 侧（HTTP 统一经 Http） */
export class Vod {
  constructor (
    private readonly http: Http,
    private readonly userId: string,
  ) { }

  async credentials (configKey = 'public_image_config'): Promise<UploadCredentials> {
    const params = fingerprintParams(this.userId, randomBytes(16).toString('hex'))
    const response = await this.http.request(`${site.web}${api.uploadConfig}?${params}`, {
      method: 'GET',
      headers: { Referer: site.referer },
    })
    const json = asRecord(JSON.parse(response.text))
    const config = asRecord(json[configKey])
    const credentials = {
      accessKeyId: String(config['access_key_id'] ?? ''),
      secretAccessKey: String(config['secret_access_key'] ?? ''),
      sessionToken: String(config['session_token'] ?? ''),
      spaceName: String(config['space_name'] ?? ''),
    }
    if (!response.ok) err(json)
    if (!credentials.accessKeyId || !credentials.secretAccessKey || !credentials.spaceName) err(config)
    return credentials
  }

  async apply (
    credentials: UploadCredentials,
    space: string,
    fileType: FileType,
    fileSize: number,
  ): Promise<UploadAddress> {
    const query = {
      Action: 'ApplyUploadInner', Version: '2020-11-19', SpaceName: space,
      FileType: fileType, IsInner: '1', NeedFallback: 'true', FileSize: String(fileSize), s: randomId(11),
      ...(fileType === 'object' ? { OpenGcmEnc: 'true' } : {}),
    }
    const json = await this.signed('GET', query, undefined, credentials)
    const result = asRecord(json['Result'])
    const direct = asRecord(result['UploadAddress'])
    const directStores = direct['StoreInfos'] as unknown[] | undefined
    const directHosts = direct['UploadHosts'] as unknown[] | undefined
    const inner = asRecord(result['InnerUploadAddress'])
    const nodes = inner['UploadNodes'] as unknown[] | undefined
    // 直连节点优先（object 通道只有 InnerUploadAddress）
    if (!nodes?.length && directStores?.length && directHosts?.length && fileType !== 'object') {
      const store = asRecord(directStores[0])
      return {
        storeUri: String(store['StoreUri'] ?? ''), authorization: String(store['Auth'] ?? ''),
        host: String(directHosts[0]), sessionKey: String(direct['SessionKey'] ?? ''),
      }
    }
    const node = asRecord(nodes?.[0])
    const stores = node['StoreInfos'] as unknown[] | undefined
    const store = asRecord(stores?.[0])
    const address: UploadAddress = {
      storeUri: String(store['StoreUri'] ?? ''), authorization: String(store['Auth'] ?? ''),
      host: String(node['UploadHost'] ?? ''), sessionKey: String(node['SessionKey'] ?? ''),
      uploadHeaders: Object.fromEntries(
        Object.entries(asRecord(node['UploadHeader'])).map(([key, value]) => [key, String(value)]),
      ),
    }
    if (fileType === 'object') {
      address.gcmMode = String(asRecord(result['SDKParam'])['server_gcm_encryption_mode'] ?? '')
      address.encryptionKey = String(asRecord(inner['AdvanceOption'])['EncryptionKey'] ?? '')
      if (!address.gcmMode || !address.encryptionKey) err(address)
    }
    if (!address.storeUri || !address.authorization || !address.host || !address.sessionKey) err(address)
    return address
  }

  async commit (
    credentials: UploadCredentials,
    sessionKey: string,
    fileType: FileType,
    imageFormat?: ImageFormat,
    address?: UploadAddress,
  ): Promise<CommittedUpload> {
    const body = Buffer.from(JSON.stringify({
      SessionKey: sessionKey,
      Functions: uploadProcessFunctions(fileType, imageFormat),
      ...(address?.gcmMode ? { EncryptionMode: address.gcmMode, EncryptionKey: address.encryptionKey } : {}),
    }))
    const json = await this.signed('POST', {
      Action: 'CommitUploadInner', Version: '2020-11-19', SpaceName: credentials.spaceName,
    }, body, credentials)
    const results = asRecord(json['Result'])['Results'] as unknown[] | undefined
    const encryption = asRecord(asRecord(results?.[0])['Encryption'])
    const extra = asRecord(encryption['Extra'])
    const committed: CommittedUpload = {
      uri: String(encryption['Uri'] ?? ''), secretKey: String(encryption['SecretKey'] ?? ''),
      sourceMd5: String(encryption['SourceMd5'] ?? ''),
    }
    const imageSize = Number(extra['img_size'])
    const imageWidth = Number(extra['img_width'])
    const imageHeight = Number(extra['img_height'])
    if (Number.isFinite(imageSize) && imageSize > 0) committed.imageSize = imageSize
    if (Number.isFinite(imageWidth) && imageWidth > 0) committed.imageWidth = imageWidth
    if (Number.isFinite(imageHeight) && imageHeight > 0) committed.imageHeight = imageHeight
    if (!committed.uri || !committed.secretKey) err(committed)
    return committed
  }

  private async signed (
    method: 'GET' | 'POST', query: Record<string, string>, body: Uint8Array | undefined,
    credentials: UploadCredentials,
  ): Promise<Record<string, unknown>> {
    const signed = signVodRequest({ method, query, ...(body ? { body } : {}), credentials, date: new Date() })
    const response = await this.http.request(`${site.vod}?${signed.canonicalQuery}`, {
      method,
      headers: {
        ...signed.headers,
        Authorization: signed.authorization,
        'User-Agent': PC_UA,
        ...(body ? { 'Content-Type': 'text/plain;charset=UTF-8' } : {}),
      },
      ...(body ? { body: new Uint8Array(body) } : {}),
    })
    const json = asRecord(JSON.parse(response.text))
    if (!response.ok) err(json)
    const error = asRecord(asRecord(json['ResponseMetadata'])['Error'])
    if (error['Code'] || error['CodeN']) err(json)
    return json
  }
}
