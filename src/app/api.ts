/** passport 请求：静态头模板 → 注入会话 → 组 body → SO 签名 → 发送 */
import { gzipSync } from 'node:zlib'
import { randomBytes } from 'node:crypto'
import type { Auth } from './auth.js'
import type { Dev, Ids } from './types.js'
import { buildUrl, panelQuery, passportQuery, ua } from './conf.js'
import { request, type Res } from './http.js'
import { ssStub, zstdCompress } from './codec.js'
import { ttEncrypt } from './crypt.js'
import { strip, type HeaderPair } from './sign/index.js'
import { soSign } from './so/index.js'
import { ask, report } from './turing.js'
import { clientData, head, staticSign, tgSec } from './guard.js'

const HOST = 'api5-normal-lf.amemv.com'
/** boot 用的设备证明入口 */
const BOOT = '/passport/user_info/get_sec_ts/'
/** 预热入口：真机取码前必带 odin_tt，该接口未登录也会下发 */
const INFO = '/passport/account/info/v2/'
/** odin_tt 有效期约 31s：留余量按 30s 刷新 */
const WARM_TTL = 30_000
/** sec-ts 有效期约 20~60s：留出余量，过期再取新票 */
const SEC_TTL = 60_000

export type Encoding = 'zstd' | 'plain' | 'tt'

export interface Send {
  auth: Auth
  dev: Dev
  ids: Ids
  path: string
  /** null = GET；string = form；Buffer = 已加密载荷（raw） */
  body?: string | Buffer | null
  enc?: Encoding
  /** 账户面板接口的 scene（normal）；登录接口不传 */
  panel?: string
  /** 额外 query 参数（如 update_scene=boot） */
  params?: Record<string, string | number>
  /** true = body 只作参数拼进 query，实际不带载荷（真机 check_qrconnect 即如此） */
  queryOnly?: boolean
  /** 覆盖请求方法；无载荷时默认 GET */
  method?: 'GET' | 'POST'
  extra?: Record<string, string>
  /** 覆盖 x-tt-request-tag：登录入口必须 s=-1，服务端才会下发 shark_admin 决策头 */
  tag?: string
  timeoutMs?: number
  /** false = 不处理 bdturing 40000（上报请求自身必须关闭，避免套娃） */
  turing?: boolean
  /** false = 跳过 ticket-guard 注入与 boot（boot 请求自身必须关闭，避免递归） */
  guard?: boolean
}

/** x-tt-trace-id 是 TTNet 生成的链路号：32hex + 其前 16hex */
function traceId (): string {
  const id = randomBytes(16).toString('hex')
  return `00-${id}-${id.slice(0, 16)}-01`
}

/** 真机静态头（顺序敏感） */
function base (dev: Dev, ids: Ids): HeaderPair[] {
  const list: HeaderPair[] = [
    ['x-tt-multi-sids', 'none'],
    ['sdk-version', '2'],
    ['passport-sdk-version', '60755'],
    ['passport-sdk-settings', 'x-tt-token,sec_user_id,device_transfer_s_0,device_transfer_ab_1'],
    ['passport-sdk-sign', 'x-tt-token,sec_user_id'],
    ['x-ss-dp', String(dev.aid)],
    ['x-tt-request-tag', 'n=0;s=-1;p=0'],
    ['x-vc-bdturing-sdk-version', '4.2.1.cn'],
    ['x-bd-kmsv', '1'],
    ['user-agent', ua(dev)],
  ]
  if (ids.device_dtrait) list.splice(1, 0, ['x-tt-device-dtrait', ids.device_dtrait])
  if (ids.device_dtrait_token) list.splice(1, 0, ['x-tt-device-dtrait-token', ids.device_dtrait_token])
  if (ids.client_key) list.push(['x-bd-client-key', ids.client_key])
  return list
}

function upsert (list: HeaderPair[], name: string, value: string | undefined): void {
  if (!value) return
  const i = list.findIndex(([n]) => n.toLowerCase() === name)
  if (i >= 0) list[i] = [list[i][0], value]
  else list.push([name, value])
}

function query (dev: Dev, ids: Ids, panel?: string, extra?: Record<string, string | number>): URLSearchParams {
  const q = passportQuery(dev, ids, {
    language: 'zh',
    first_launch_timestamp: ids.first_install,
    last_deeplink_update_version_code: 0,
    is_guest_mode: 0,
    app_type: 'normal',
    minor_status: 0,
    is_preinstall: 0,
    need_personal_recommend: 1,
    is_android_pad: 0,
    is_android_fold: 0,
    cronet_version: '295fdb87_2026-08-31',
    ttnet_version: '4.2.301.9-douyin',
    ...extra,
  })
  return panel ? panelQuery(q, panel) : q
}

/** 取/复用 sec-ts：注册与业务请求共用同一套证明材料，缺票时先 boot */
export async function boot (auth: Auth, dev: Dev, ids: Ids): Promise<string> {
  const fixed = tgSec()
  if (fixed) {
    auth.sec = fixed
    return fixed
  }
  if (auth.sec && Date.now() - auth.secAt < SEC_TTL) return auth.sec
  const ts = Math.floor(Date.now() / 1000)
  const res = await once({
    auth,
    dev,
    ids,
    path: BOOT,
    params: { update_scene: 'boot' },
    body: 'update_scene=boot',
    enc: 'zstd',
    guard: false,
    extra: Object.fromEntries(head(dev, ids, 2, [['bd-ticket-guard-client-data', clientData(ids, BOOT, '', ts)]])),
  })
  const sec = res.headers['bd-ticket-guard-sec-ts']
  if (sec) {
    auth.sec = sec
    auth.secAt = Date.now()
  }
  return auth.sec
}

/** 真机会在正常浏览中拿到 odin_tt（TTNet 反爬 cookie）；全新会话缺失时 passport 会兜底判 7 */
export async function warm (auth: Auth, dev: Dev, ids: Ids): Promise<void> {
  if (auth.jar.has('odin_tt') && Date.now() - auth.warmAt < WARM_TTL) return
  auth.warmAt = Date.now()
  await once({ auth, dev, ids, path: INFO, panel: 'normal', body: null })
}

/** 发一条 passport 请求，成功与否都回写会话 cookie/头 */
export async function send (init: Send): Promise<Res> {
  if (init.guard !== false) {
    await boot(init.auth, init.dev, init.ids)
    await warm(init.auth, init.dev, init.ids)
  }
  const res = await once(init)
  if (init.turing === false) return res
  // 40000 是服务端要求先做静默采集：上报成功后原请求重放一次即可放行
  const a = ask(res)
  if (!a || !(await report(a, init.dev, init.ids, init.auth))) return res
  return once(init)
}

/**
 * 端上通用请求头：passport 与 bdturing 请求共用同一套会话与设备证明。
 * 真机的 /captcha/get|verify 带完整 passport cookie、x-tt-token、csrf、ticket-guard 头，
 * 少了这些挑战票据无法归属到会话，verify 会被判环境异常（5014）。
 */
export function headOf (auth: Auth, dev: Dev, ids: Ids, tag: string, guard = true, extra?: Record<string, string>): HeaderPair[] {
  const headers = strip(base(dev, ids))
  const cookie = auth.cookie()
  if (cookie) headers.push(['cookie', cookie])
  upsert(headers, 'x-tt-passport-csrf-token', auth.csrf())
  upsert(headers, 'x-tt-dt', ids.device_token)
  upsert(headers, 'x-tt-passport-verify-portrait', auth.portrait)
  upsert(headers, 'x-tt-passport-verify-portrait-outer', auth.portrait)
  upsert(headers, 'x-tt-passport-trace-id', auth.traceId)
  upsert(headers, 'x-tt-passport-mfa-token', auth.mfaToken)
  upsert(headers, 'd-ticket', auth.dTicket)
  // TTNet 每次请求都会带的时间/链路头；缺失会被当成非端上请求
  const ms = Date.now()
  upsert(headers, 'activity_now_client', String(ms))
  upsert(headers, 'x-ss-req-ticket', String(ms))
  upsert(headers, 'x-tt-trace-id', traceId())
  for (const n of ['x-tt-token', 'x-tt-token-supplement', 'token-tlb-tag', 'session-tlb-tag']) upsert(headers, n, auth.tokens[n])
  upsert(headers, 'x-tt-request-tag', tag)
  for (const [k, v] of Object.entries(extra ?? {})) upsert(headers, k.toLowerCase(), v)
  // 设备证明与新注册的 device_id 绑定；自造的 x-bb-* 与真机同源材料不一致，扫码确认后会被判 7
  // 迭代版本与真机抓包一致（2）；static-sign 回执 1003 是材料版本提示，不影响业务请求
  if (guard && auth.sec) {
    for (const [k, v] of head(dev, ids, 2, [
      ['bd-ticket-guard-static-sign', staticSign(ids, auth.sec)],
      ['bd-ticket-guard-sec-ts', auth.sec],
    ])) upsert(headers, k, v)
  }
  return headers
}

async function once (init: Send): Promise<Res> {
  const { auth, dev, ids } = init
  const q = query(dev, ids, init.panel, init.params)
  // 真机把表单参数并进查询串、载荷留空；两者都发会多出一份不一致的副本
  if (init.queryOnly && typeof init.body === 'string') {
    for (const [k, v] of new URLSearchParams(init.body)) if (!q.has(k)) q.set(k, v)
  }
  const url = buildUrl(HOST, init.path, q)
  const headers = headOf(auth, dev, ids, init.tag ?? 'n=0;s=-1;p=0', init.guard !== false, init.extra)

  let payload: Buffer | undefined
  let signText: string | undefined
  let signBytes: Buffer | undefined
  const body = init.queryOnly ? null : init.body
  if (body !== null && body !== undefined) {
    const enc = init.enc ?? 'zstd'
    if (Buffer.isBuffer(body)) {
      payload = body
      signBytes = body
      headers.push(['content-type', 'application/octet-stream'])
    } else if (enc === 'tt') {
      // x-ss-stub 与 X-Gorgon 都按 ttEncrypt 密文算；gzip 只是传输层，若按压缩后算会被判 7
      const plain = Buffer.from(body, 'utf8')
      const encrypted = ttEncrypt(plain)
      payload = gzipSync(encrypted)
      signBytes = encrypted
      headers.push(['content-type', 'application/x-www-form-urlencoded; charset=UTF-8'])
      headers.push(['x-bd-content-encoding', 'gzip'])
      headers.push(['x-tt-encrypt-info', '1'])
      headers.push(['x-tt-cipher-version', '1.0.0'])
      headers.push(['x-ss-stub', ssStub(encrypted)])
    } else {
      const plain = Buffer.from(body, 'utf8')
      payload = enc === 'zstd' ? zstdCompress(plain) : plain
      // 签名用明文，zstd 仅传输层
      signText = body
      headers.push(['content-type', 'application/x-www-form-urlencoded; charset=UTF-8'])
      if (enc === 'zstd') headers.push(['x-bd-content-encoding', 'zstd'])
      headers.push(['x-ss-stub', ssStub(plain)])
    }
    headers.push(['content-length', String(payload.length)])
  }
  headers.push(['accept-encoding', 'gzip, deflate'])

  // 六神头必须由 .so 生成：纯算的 x-gorgon arg1 段与真机不一致，服务端会判 7
  const bits = signBytes ?? (signText !== undefined ? Buffer.from(signText, 'utf8') : undefined)
  const sig = soSign(url, bits, { deviceId: ids.device_id, installId: ids.iid })
  for (const [k, v] of Object.entries(sig)) {
    // x-ss-stub 按传输前的密文/明文算，与 SO 内的摘要口径不同，保留本地值
    if (k !== 'x-ss-stub') upsert(headers, k, v)
  }

  const res = await request({ url, method: init.method ?? (payload ? 'POST' : 'GET'), headers, body: payload, timeoutMs: init.timeoutMs })
  auth.absorb(res.setCookie)
  auth.lastHeaders = res.headers
  auth.take(res.headers)
  return res
}
