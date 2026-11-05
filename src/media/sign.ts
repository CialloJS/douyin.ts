import { createHash, createHmac, randomBytes } from 'node:crypto'
import { vod } from '../session/codes.js'
import type { UploadCredentials, VodSignature } from '../types.js'

/**
 * VOD 走 AWS Signature V4：签名串与 query 必须逐字节一致，
 * 故规范化/派生集中在此，调用方只负责拼业务参数。
 */

function hashHex (data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex')
}

function hmac (key: Uint8Array | string, value: string): Buffer {
  return createHmac('sha256', key).update(value).digest()
}

function rfc3986 (value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) =>
    `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  )
}

export function canonicalUploadQuery (query: Record<string, string>): string {
  return Object.keys(query)
    .sort()
    .map((key) => `${rfc3986(key)}=${rfc3986(query[key]!)}`)
    .join('&')
}

/** ByteDance VOD 上传用的纯 AWS Signature V4 实现 */
export function signVodRequest (options: {
  method: 'GET' | 'POST'
  query: Record<string, string>
  body?: Uint8Array
  credentials: UploadCredentials
  date: Date
}): VodSignature {
  const canonicalQuery = canonicalUploadQuery(options.query)
  const amzDate = options.date.toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dateStamp = amzDate.slice(0, 8)
  const payloadHash = hashHex(options.body ?? new Uint8Array())
  const headers: Record<string, string> = {
    'x-amz-date': amzDate,
    'x-amz-security-token': options.credentials.sessionToken,
  }
  if (options.method === 'POST') headers['x-amz-content-sha256'] = payloadHash
  const headerNames = Object.keys(headers).sort()
  const canonicalHeaders = headerNames.map((name) => `${name}:${headers[name]}\n`).join('')
  const signedHeaders = headerNames.join(';')
  const canonicalRequest = [
    options.method, '/', canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
  ].join('\n')
  const scope = `${dateStamp}/${vod.region}/${vod.service}/aws4_request`
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${hashHex(canonicalRequest)}`
  let signingKey = hmac(`AWS4${options.credentials.secretAccessKey}`, dateStamp)
  signingKey = hmac(signingKey, vod.region)
  signingKey = hmac(signingKey, vod.service)
  signingKey = hmac(signingKey, 'aws4_request')
  const signature = hmac(signingKey, stringToSign).toString('hex')
  return {
    canonicalQuery,
    headers,
    authorization:
      `AWS4-HMAC-SHA256 Credential=${options.credentials.accessKeyId}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`,
  }
}

/** ApplyUpload 的 s 参数只需不可预测，避免 CDN 命中上一轮残留对象 */
export function randomId (length: number): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
  return [...randomBytes(length)].map((byte) => alphabet[byte % alphabet.length]).join('')
}
