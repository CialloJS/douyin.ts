/** 纯算六神签名（无 so / 无抓包依赖）；算法体移植自参考实现，只改导入与命名 */
import { randomBytes } from 'node:crypto'
import { argus } from './argus.js'
import { gorgon } from './gorgon.js'
import { helios } from './helios.js'
import { ladon } from './ladon.js'
import { medusa } from './medusa.js'
import { ssStub } from './hash.js'

export type HeaderPair = [string, string]

export interface SignInput {
  url: string
  headers: HeaderPair[]
  /** POST 明文 body（用于现算 x-ss-stub） */
  body?: string
  /** POST 二进制 body（加密后 pb / ttEncrypt） */
  bodyBytes?: Buffer
  deviceIds?: { deviceId?: string }
}

/** 需要重算的头，套模板时先剔除 */
export const SIG_HEADERS = [
  'x-perseus',
  'x-medusa',
  'x-argus',
  'x-gorgon',
  'x-helios',
  'x-ladon',
  'x-khronos',
] as const

function headerOf (pairs: HeaderPair[], name: string): string | undefined {
  const low = name.toLowerCase()
  for (let i = pairs.length - 1; i >= 0; i--) {
    if (pairs[i][0].toLowerCase() === low) return pairs[i][1]
  }
  return undefined
}

function queryOf (url: string): string {
  try {
    const q = new URL(url).search
    return q.startsWith('?') ? q.slice(1) : q
  } catch {
    const i = url.indexOf('?')
    return i < 0 ? '' : url.slice(i + 1)
  }
}

/** 去掉模板里的旧签名头，必须重签 */
export function strip (pairs: HeaderPair[]): HeaderPair[] {
  const low = new Set<string>(SIG_HEADERS)
  return pairs.filter(([k]) => !low.has(k.toLowerCase()))
}

export function sign (input: SignInput): Record<string, string> {
  const query = queryOf(input.url)
  const ts = Math.floor(Date.now() / 1000)
  const rb = randomBytes(4)
  const stub =
    headerOf(input.headers, 'x-ss-stub') ??
    (input.bodyBytes && input.bodyBytes.length > 0
      ? ssStub(input.bodyBytes)
      : typeof input.body === 'string' && input.body.length > 0
        ? ssStub(input.body)
        : undefined)

  const headers: Record<string, string> = {}
  Object.assign(headers, ladon({ unix: ts, random: rb }))
  Object.assign(headers, gorgon({ query, commonParams: headerOf(input.headers, 'x-common-params-v2'), stub, unix: ts }))
  Object.assign(headers, argus({ unix: ts }))
  Object.assign(headers, helios({ unix: ts, aid: 1128 }))
  Object.assign(headers, medusa({ unix: ts, query, deviceId: input.deviceIds?.deviceId, random: rb.subarray(0, 2) }))
  return headers
}
