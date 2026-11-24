/** IM 网关：端到端明文 pb + ChaCha20 整包加密（x-tt-e-b/e-p/e-t） */
import { randomBytes } from 'node:crypto'
import type { Dev, Ids } from './types.js'
import type { Auth } from './auth.js'
import { buildUrl, socialQuery, ua } from './conf.js'
import { request } from './http.js'
import { ssStub, zstdCompress } from './codec.js'
import { sign, strip, type HeaderPair } from './sign/index.js'
import { handshake, chacha20, MARGIN, type ImSession } from './keyhub.js'
import { DOMAIN } from './rest.js'
import type { Res } from './http.js'

export const HOST = 'api5-social-m-jj.amemv.com'

export type Enc = 'pb' | 'json' | 'form' | 'zstd-json' | 'zstd-form' | 'none'

export interface Endpoint {
  path: string
  method: 'GET' | 'POST'
  enc: Enc
  host?: string
}

/**
 * path 以真机抓包为准：会话/消息/已读三个 pb 接口不带 /aweme 前缀，
 * enter_chat 与 active/status 带尾斜杠；前缀不对会命中网关兜底路由（200 空 body / 3105）。
 */
export const IM_ENDPOINTS = {
  conversationInfo: { path: '/v2/conversation/get_info', method: 'POST', enc: 'pb' },
  conversationInfoList: { path: '/v2/conversation/get_info_list', method: 'POST', enc: 'pb', host: 'api5-social-m-lf.amemv.com' },
  markRead: { path: '/v3/conversation/mark_read', method: 'POST', enc: 'pb' },
  getByConversation: { path: '/v1/message/get_by_conversation', method: 'POST', enc: 'pb' },
  userMessage: { path: '/v3/message/get_user_message', method: 'POST', enc: 'pb' },
  enterChat: { path: '/aweme/v1/im/service/enter_chat/', method: 'POST', enc: 'zstd-json' },
  activeStatus: { path: '/aweme/v1/im/user/active/status/', method: 'POST', enc: 'form' },
  groupOnline: { path: '/aweme/v1/im/user/group/online', method: 'GET', enc: 'none' },
  bulletEvent: { path: '/aweme/v1/im/bullet/common_event/request_and_update', method: 'POST', enc: 'json' },
  groupEntryLimit: { path: '/aweme/v1/im/group/settings/entry_limit', method: 'GET', enc: 'none' },
  otherScene: { path: '/aweme/v2/im/conversation/info/other/scene', method: 'GET', enc: 'none' },
  otherInfo: { path: '/aweme/v1/im/conversation/info/other', method: 'POST', enc: 'form' },
  floatingBarCheck: { path: '/aweme/v1/im/conversation/floating_bar/check', method: 'GET', enc: 'none' },
  floatingBarConfigs: { path: '/aweme/v1/im/conversation/floating_bar/configs', method: 'GET', enc: 'none' },
  emoticonSearch: { path: '/aweme/v1/im/resources/emoticon/search', method: 'GET', enc: 'none' },
  hellosticker: { path: '/aweme/v1/im/hellosticker', method: 'GET', enc: 'none' },
  imageUpload: { path: '/aweme/v1/im/image/upload', method: 'POST', enc: 'pb' },
} as const satisfies Record<string, Endpoint>

export type ImName = keyof typeof IM_ENDPOINTS

export interface Call {
  name?: ImName
  /** 覆盖/自定义路径 */
  path?: string
  /** 覆盖端点 host（业务接口分散在 core/platform/normal 等域） */
  host?: string
  method?: 'GET' | 'POST'
  /** 覆盖端点编码 */
  enc?: Enc
  body?: Buffer | string
  query?: Record<string, string | number>
  headers?: Record<string, string>
  /** pb body 是否加密，默认 true */
  encrypt?: boolean
  /** 复用 keyhub 会话 */
  session?: ImSession
  timeoutMs?: number
}

export interface ImRes {
  status: number
  headers: Record<string, string>
  raw: Buffer
  text: string
  json?: unknown
  /** 响应体可直接解析：加密响应已解开，或服务端本就返回明文 */
  ready: boolean
}

export interface ImOpts {
  dev: Dev
  ids: Ids
  auth: Auth
}

function base (dev: Dev, ids: Ids): HeaderPair[] {
  const list: HeaderPair[] = [
    ['x-tt-multi-sids', 'none'],
    ['sdk-version', '2'],
    ['x-ss-dp', String(dev.aid)],
    ['x-tt-request-tag', 'n=0;s=-1;p=0'],
    ['x-vc-bdturing-sdk-version', '4.2.1.cn'],
    ['x-tt-dt', ids.device_token],
    ['user-agent', ua(dev)],
  ]
  if (ids.device_dtrait) list.splice(2, 0, ['x-tt-device-dtrait', ids.device_dtrait])
  if (ids.device_dtrait_token) list.splice(2, 0, ['x-tt-device-dtrait-token', ids.device_dtrait_token])
  if (ids.client_key) list.push(['x-bd-client-key', ids.client_key])
  return list
}

function find (pairs: HeaderPair[], name: string): string | undefined {
  const ln = name.toLowerCase()
  for (let i = pairs.length - 1; i >= 0; i--) if (pairs[i][0].toLowerCase() === ln) return pairs[i][1]
  return undefined
}

function put (pairs: HeaderPair[], name: string, value: string): void {
  const ln = name.toLowerCase()
  const i = pairs.findIndex(([n]) => n.toLowerCase() === ln)
  if (i >= 0) pairs[i] = [pairs[i][0], value]
  else pairs.push([name, value])
}

export class Im {
  readonly dev: Dev
  readonly ids: Ids
  private readonly auth: Auth
  private tk?: string
  private id?: string
  session?: ImSession

  constructor (opts: ImOpts) {
    this.dev = opts.dev
    this.ids = opts.ids
    this.auth = opts.auth
  }

  /** 取未临近过期的 IM 会话（首次触发 keyhub 握手） */
  async key (force = false): Promise<ImSession> {
    if (!force && this.session && this.session.deviceId === this.ids.device_id && Date.now() < this.session.expiresAt - MARGIN) {
      return this.session
    }
    this.session = await handshake(this.ids.device_id)
    return this.session
  }

  /** 信封 token：真机取 fetchMixInit 下发的 im_token，取不到退化用 sessionid */
  async token (): Promise<string> {
    if (this.tk) return this.tk
    try {
      const res = await this.call({ path: '/aweme/v1/im/reboot/misc/', method: 'GET' })
      const t = (res.json as Record<string, unknown> | undefined)?.im_token
      if (typeof t === 'string' && t) this.tk = t
    } catch {
      // 配置接口失败时用登录态兜底，避免整个 pb 链路不可用
    }
    this.tk ??= String(this.auth.jar.get('sessionid') ?? '')
    return this.tk
  }

  /** 登录 uid：x-tt-e-k 必须是 uid+IM，cookie 里没有，只能从自身资料取一次 */
  async uid (): Promise<string> {
    if (this.id) return this.id
    try {
      const res = await this.call({ path: '/aweme/v1/user/profile/self/', host: DOMAIN.core, method: 'GET' })
      const u = (res.json as { user?: { uid?: unknown } } | undefined)?.user?.uid
      if (u != null) this.id = String(u)
    } catch {
      // 取不到时留空，服务端会直接回 auth 错误
    }
    return this.id ?? String(this.auth.jar.get('uid') ?? '')
  }

  async call (call: Call = {}): Promise<ImRes> {
    const ep = call.name ? (IM_ENDPOINTS[call.name] as Endpoint) : undefined
    const enc = call.enc ?? ep?.enc ?? (call.body ? 'pb' : 'none')
    const method = call.method ?? ep?.method ?? (call.body ? 'POST' : 'GET')
    const q = socialQuery(this.dev, this.ids, call.query)
    const url = buildUrl(call.host ?? ep?.host ?? HOST, call.path ?? ep?.path ?? '/', q, {})
    const pairs = strip(base(this.dev, this.ids))

    const cookie = this.auth.cookie()
    if (cookie) pairs.push(['cookie', cookie])
    for (const n of ['x-tt-token', 'x-tt-token-supplement']) {
      const v = this.auth.tokens[n]
      if (v) pairs.push([n, v])
    }
    for (const [k, v] of Object.entries(call.headers ?? {})) put(pairs, k.toLowerCase(), v)

    let payload: Buffer | undefined
    let text: string | undefined
    let sbytes: Buffer | undefined
    let keyIM: Buffer | undefined
    if (call.body !== undefined) {
      const body = Buffer.isBuffer(call.body) ? call.body : Buffer.from(call.body, 'utf8')
      if (enc === 'pb') {
        payload = body
        put(pairs, 'content-type', 'application/x-protobuf')
        if (call.encrypt !== false) {
          const sess = call.session ?? (await this.key())
          keyIM = sess.keyIM
          const nonce = Buffer.from(find(pairs, 'x-tt-e-p') ?? '', 'base64')
          const use = nonce.length === 12 ? nonce : randomBytes(12)
          payload = chacha20(keyIM, use, body)
          put(pairs, 'x-tt-e-b', '1')
          put(pairs, 'x-tt-e-p', use.toString('base64'))
          put(pairs, 'x-tt-e-t', find(pairs, 'x-tt-e-t') ?? sess.ticket)
          put(pairs, 'x-ss-stub', ssStub(body))
          const uid = await this.uid()
          if (uid) put(pairs, 'x-tt-e-k', `${uid}+IM`)
          sbytes = payload
        } else {
          sbytes = payload
        }
      } else if (enc === 'zstd-json' || enc === 'zstd-form') {
        payload = zstdCompress(body)
        text = body.toString('utf8')
        put(pairs, 'content-type', enc === 'zstd-json' ? 'application/json' : 'application/x-www-form-urlencoded')
        put(pairs, 'x-bd-content-encoding', 'zstd')
        put(pairs, 'x-ss-stub', ssStub(body))
      } else {
        payload = body
        text = body.toString('utf8')
        put(pairs, 'content-type', enc === 'json' ? 'application/json' : 'application/x-www-form-urlencoded')
        if (enc === 'form' || enc === 'json') put(pairs, 'x-ss-stub', ssStub(body))
      }
      put(pairs, 'content-length', String(payload.length))
    }
    put(pairs, 'accept-encoding', 'gzip, deflate, br')

    const sig = sign({ url, headers: pairs, body: text, bodyBytes: sbytes, deviceIds: { deviceId: this.ids.device_id } })
    for (const [k, v] of Object.entries(sig)) pairs.push([k, v])

    const res = await request({ url, method, headers: pairs, body: payload, timeoutMs: call.timeoutMs })
    this.auth.absorb(res.setCookie)
    return decode(res, keyIM)
  }
}

function decode (res: Res, key?: Buffer): ImRes {
  let raw = res.body
  // 没有 x-tt-e-p 说明服务端返回的是明文（错误 envelope 就是这种），此时无需解密即可解析
  let ready = true
  const nonce = res.headers['x-tt-e-p']
  if (key && nonce && raw.length > 0 && res.status === 200) {
    try {
      raw = chacha20(key, Buffer.from(nonce, 'base64'), raw)
    } catch {
      // 解密失败保留原始字节，交给调用方按不可解析处理
      ready = false
    }
  } else if (nonce && raw.length > 0 && res.status === 200) {
    ready = false
  }
  const text = raw.toString('utf8')
  const ct = res.headers['content-type'] ?? ''
  let json: unknown
  if (ct.includes('json') || /^[{\[]/.test(text.trimStart())) {
    try {
      json = JSON.parse(text)
    } catch {
      json = undefined
    }
  }
  return { status: res.status, headers: res.headers, raw, text, json, ready }
}
