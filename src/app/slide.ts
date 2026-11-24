/** 1105 滑块本地验证页：官方 bdturing SDK 在本次决策上完成验证，通过后上层自动回填票据重发 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import * as http from 'node:http'
import * as os from 'node:os'
import { join } from 'node:path'
import { createLog } from '../session/log.js'
import { findAsset } from '../asset.js'
import { solve } from './auto.js'
import type { Auth } from './auth.js'
import type { Challenge } from './captcha.js'
import type { Dev, Ids } from './types.js'
import { request, type Res } from './http.js'
import { soSign } from './so/index.js'
import { ua } from './conf.js'
import { headOf } from './api.js'

const log = createLog({ tag: 'slide' })

/** 只放行抖音自家的验证域，避免本地服务被当成任意代理 */
const PROXY_ALLOW = /(^|\.)(zijieapi\.com|bytedance\.com|snssdk\.com|amemv\.com)$/i

/** 真机 /captcha/* 的接入点由决策的 server_sdk_env.idc 决定（HAR 实测 verify-lf）；写死会与设备区域不符 */
function appHost (challenge: Challenge): string {
  const env = challenge.decision.server_sdk_env
  const raw = typeof env === 'string' ? env : JSON.stringify(env ?? {})
  try {
    const idc = (JSON.parse(raw) as { idc?: string }).idc
    if (idc) return `https://verify-${idc}.zijieapi.com`
  } catch {
    // 决策里没有合法 JSON 时退回 HAR 实测的接入点
  }
  return 'https://verify-lf.zijieapi.com'
}
const PAGE_HOST = 'https://verify.zijieapi.com'
/** HAR 里 /captcha/* 只带这一个 cookie；串入 passport 会话会暴露「同一 did 既像浏览器又持有 App 会话」 */
const CAPTCHA_COOKIE = 'ticket_guard_has_set_public_key=1'

/** 内置 SDK 副本；缺失时留空，让上层跳过滑块 */
const SDK_DIR = findAsset('captcha.1.0.0.1007.js')
const SDK_FILE = SDK_DIR ? join(SDK_DIR, 'captcha.1.0.0.1007.js') : ''

export interface SlideOpts {
  /** 监听端口，默认 8787 */
  port?: number
  /** 等待拖动的最长时间，默认 5 分钟 */
  timeoutMs?: number
  /** 页面地址回调（默认只打印到日志）；需自定义二维码时可在这里处理 */
  onUrl?: (url: string) => void | Promise<void>
}

export interface SlideInput extends SlideOpts {
  challenge: Challenge
  dev: Dev
  ids: Ids
  auth: Auth
  /** 本次验证所属登录事件；真机 native SDK 会把它写进 verify_data */
  event?: string
}

/** 一次验证的结果：ok 通过；fail 拖错；cool 5014；timeout 用户没拖；closed 被关闭 */
export type Result = 'ok' | 'fail' | 'cool' | 'timeout' | 'closed'

export interface Slide {
  /** 手机扫码/输入打开的地址 */
  readonly url: string
  readonly port: number
  /** 已转发请求，便于排查 */
  readonly hits: string[]
  /** 通过为 true；失败/超时/关闭为 false */
  wait(): Promise<boolean>
  /** 结束原因：失败后上层要据此决定是否重新向服务端取决策 */
  result(): Result
  close(): void
}

/** verify_center 是验证中心下发给网页/H5 的决策：改写成 App 通道后「声明」与验证体来源矛盾，实测 5014 */
function h5 (): boolean {
  return process.env.DY_H5 === '1'
}

/** 真机滑块通道固定上报整屏 1272*2800；passport 其他接口声明的是可用区 1272*2603，两者不能混用 */
function captchaResolution (): string {
  return process.env.DY_CAPTCHA_RESOLUTION ?? '1272*2800'
}

/** 真机 /captcha/get|verify 的 App 通道参数（HAR 抄录）；浏览器形态的 UA + web 参数会被判 5014 */
function appQuery (dev: Dev, ids: Ids, subtype: string): URLSearchParams {
  const did = ids.device_id
  const base: Array<[string, string | number]> = [
    ['aid', dev.aid],
    ['lang', 'zh'],
    ['bd_version', '1.0.0.1007'],
    ['subtype', subtype],
    ['mode', subtype],
    ['did', did],
    ['device_id', did],
    ['os_name', dev.os],
    ['platform', 'app'],
    ['os_type', 0],
    ['h5_sdk_version', '3.5.81'],
    ['webdriver', 'false'],
    ['tmp', Date.now()],
    ['verify_host', 'https://verify.zijieapi.com/'],
    ['app_name', dev.appName],
    ['locale', 'zh_CN'],
    ['ch', dev.channel],
    ['channel', dev.channel],
    ['iid', ids.iid],
    ['vc', dev.versionName],
    // 真机字段名就是拼错的 app_verison，改名会少一个参数
    ['app_verison', dev.versionName],
    ['region', 'cn'],
    ['use_native_report', 1],
    ['use_jsb_request', 1],
    ['verify_cancellable', 0],
    ['orientation', 0],
    ['resolution', captchaResolution()],
    ['sdk_version', '4.2.1.cn'],
    ['os_version', dev.osVersion],
    ['device_brand', dev.deviceBrand],
    ['device_model', dev.deviceType],
    ['version_code', dev.manifestVersionCode],
    ['version_name', dev.versionName],
    ['device_type', dev.deviceType],
    ['device_platform', dev.devicePlatform],
    ['use_dialog_size_v2', 1],
  ]
  const q = new URLSearchParams()
  for (const [k, v] of base) q.set(k, String(v))
  return q
}

/**
 * 把页面 SDK 发往 verify.zijieapi.com 的 /captcha/* 改写成真机 App 请求。
 * 必须保留 SDK 自己的 query：页面 SDK 会把 challenge 绑定的加密字段塞在 URL 里，
 * 整包重建只剩抄来的常量，服务端就认不出这是它自己下发的环境。
 * a_bogus / msToken 由页面 SDK 按当前环境现算，删掉等于让一条自报 app 的请求缺环境凭据：
 * 实测删掉恒 5014，保留才有 200。
 */
function rewrite (target: string, dev: Dev, ids: Ids, challenge: Challenge): string {
  const u = new URL(target)
  const q = new URLSearchParams(u.searchParams)
  for (const [k, v] of appQuery(dev, ids, challenge.subtype || 'slide')) q.set(k, v)
  // 防重放时间戳每条请求都要现算
  q.set('tmp', String(Date.now()))
  // 只有 verify 把 verify_data 换成整包 decision（含 verify_ticket / log_id），
  // 这是「通过后记到哪个 challenge」的关联凭据；get 保留 SDK 自己的值，
  // 它带的是本次 get 的 challenge 上下文，换掉会被判两个请求不属于同一次挑战
  if (/\/captcha\/verify$/i.test(u.pathname)) {
    const d: Record<string, unknown> = { ...challenge.decision }
    if (!d['verify_ticket'] && challenge.verifyTicket) d['verify_ticket'] = challenge.verifyTicket
    q.delete('verify_data')
    q.append('verify_data', JSON.stringify(d))
  }
  return `${appHost(challenge)}${u.pathname}?${q.toString()}`
}

const esc = (v: unknown): string => JSON.stringify(v).replace(/</g, '\\u003c')

/**
 * 自建验证页：不代理官方 rmc 页，因为官方页会把浏览器指纹塞进 env 上报，
 * 与 App 通道声明的设备互相矛盾，bdturing 直接回 5014。
 * 轨迹与加密体由官方 SDK 自己算。env 也必须是 SDK 原样采集：SDK 会检测 navigator/WebGL
 * 上的 JS 覆盖（defineProperty），命中后会把 GPU/触摸数据抹掉，服务端判环境不可信 → 5014。
 * 所以这里不做任何指纹改写，移动形态只通过 Playwright 的 UA/视口/触摸真实模拟。
 */
function page (decision: Record<string, unknown>, dev: Dev, ids: Ids): string {
  const info = {
    aid: dev.aid,
    appName: dev.appName,
    lang: 'zh',
    // H5 通道下 did 会被 SDK 透传进 /captcha/get，服务端按参数错误拒绝；App 通道由 rewrite 统一补
    did: h5() ? '' : ids.device_id,
    iid: h5() ? ids.iid : '',
    fp: '',
    repoId: '',
    pageId: '',
  }
  // decision 内联，避免把几 KB 的 verify_data 塞进二维码地址
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>安全验证</title>
<style>
 html,body{margin:0;height:100%;background:#f6f7f9;font:14px/1.5 -apple-system,"Segoe UI",Arial,sans-serif}
 #wrap{max-width:420px;margin:24px auto;background:#fff;border-radius:10px;padding:16px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
 #hint{color:#666;margin:0 0 12px}
 #out{white-space:pre-wrap;word-break:break-all;color:#666;margin-top:12px;font-size:12px}
</style></head>
<body>
<div id="wrap">
  <p id="hint">加载中…</p>
  <div id="captcha_container"></div>
  <div id="out"></div>
</div>
<script>
window.gfdatav1 = {env:'prod', ver:'1.0.0.1007'};
window.bdCaptcha_slardar = function(){};
window.collectEvent = function(){};
</script>
<script src="/captcha-sdk.js" crossorigin="anonymous"></script>
<script>
(function(){
  var Q = ${esc(info)}, VD = ${esc(JSON.stringify(decision))};
  var hint = document.getElementById('hint');
  try {
    var N = {aid: Q.aid, appName: Q.appName, lang: Q.lang,
             fp: Q.fp || '', repoId: Q.repoId || '', pageId: Q.pageId || ''};
    if (Q.did) N.did = Q.did;
    if (Q.iid) N.iid = Q.iid;
    var c = new window.bdCaptcha.CaptchaVerify({
      info: N,
      ele: 'captcha_container',
      host: location.origin,
      viewport: false,
      hideCloseBtn: true,
      theme: {},
      env: {},
      successCb: function(){ hint.textContent = '验证通过，请回到电脑继续'; },
      closeCb: function(){},
      feedbackSubmitCb: function(){},
      log: function(){}
    });
    c.init();
    c.render(VD);
    // 环境指纹是异步采集的，加载后立刻拖会采不全 → 服务端判环境不可信
    hint.textContent = '等“拼图”出现 2~3 秒再拖';
  } catch (e) {
    hint.textContent = '验证组件加载失败：' + e;
  }
})();
</script>
</body></html>`
}

function readBody (req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

function lanIp (): string {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const item of list ?? []) {
      if (item.family === 'IPv4' && !item.internal) return item.address
    }
  }
  return '127.0.0.1'
}

/**
 * /captcha/* 的请求头。
 * 默认只发 bdturing 自身需要的头（真机 HAR 里 /captcha/* 也只带那一个公钥 cookie）。
 * DY_CAPTCHA=full 时改用 passport 会话票据头做单变量排查：api.ts 的注释断言缺票据会被判 5014，
 * 而 unidbg 抓包显示真机 /captcha/* 确实不带会话票据；两说矛盾，用实测裁决。
 * DY_CAPTCHA=plain 时连 App 签名头也不加：验证体是网页 SDK 采的，App 网关签名与它是否自洽需单变量实测。
 */
/** 排查用：把真机抓到的 x-bdms-payload 塞进 verify 体，验证服务端是否强制要求这个原生环境上报字段 */
function withBdms (body: Buffer): Buffer {
  const file = process.env.DY_BDMS
  if (!file) return body
  try {
    const j = JSON.parse(body.toString('utf8')) as Record<string, unknown>
    j['x-bdms-payload'] = readFileSync(file, 'utf8').trim()
    return Buffer.from(JSON.stringify(j))
  } catch {
    return body
  }
}

async function sendCaptcha (target: string, method: 'GET' | 'POST', body: Buffer, type: string | undefined, dev: Dev, ids: Ids, auth: Auth, sign: boolean): Promise<Res> {
  const u = new URL(target)
  if (!PROXY_ALLOW.test(u.hostname)) throw new Error(`拒绝代理: ${u.hostname}`)
  const cm = process.env.DY_CAPTCHA
  const full = cm === 'full'
  const plain = cm === 'plain'
  const headers: Array<[string, string]> = full
    ? headOf(auth, dev, ids, 'n=1;t=0;s=-1;p=0', true)
    : [
        ['user-agent', ua(dev)],
        ['x-ss-dp', String(dev.aid)],
        ['cookie', CAPTCHA_COOKIE],
      ]
  headers.push(['x-vc-bdturing-sdk-version', '4.2.1.cn'])
  // 真机 /captcha/get 没有 body 也带 content-type
  headers.push(['content-type', type ?? 'application/json; charset=utf-8'])
  if (sign && !plain) {
    // 真机 /captcha/verify 带设备证书；缺它等于声明「有 App 会话却没有设备凭证」
    if (ids.client_key && !full) headers.push(['x-bd-client-key', ids.client_key])
    try {
      const sig = soSign(target, body.length ? body : undefined, { deviceId: ids.device_id, installId: ids.iid })
      for (const [k, v] of Object.entries(sig)) headers.push([k, v])
    } catch (e) {
      log.warn(`verify 签名失败，服务端会按风控处理：${String(e).slice(0, 200)}`)
    }
  }
  return request({ url: target, method, headers, body: body.length ? body : undefined })
}

/** H5 通道：决策 from=verify_center 时验证体本就是网页 SDK 采的，原样透传浏览器请求才自洽 */
async function sendH5 (target: string, method: 'GET' | 'POST', body: Buffer, type: string | undefined, uaText: string): Promise<Res> {
  const u = new URL(target)
  if (!PROXY_ALLOW.test(u.hostname)) throw new Error(`拒绝代理: ${u.hostname}`)
  const headers: Array<[string, string]> = [
    ['user-agent', uaText],
    ['accept', '*/*'],
    ['accept-language', 'zh-CN,zh;q=0.9'],
    ['x-vc-bdturing-sdk-version', '4.2.1.cn'],
    ['cookie', CAPTCHA_COOKIE],
    ['content-type', type ?? 'application/json; charset=utf-8'],
  ]
  return request({ url: target, method, headers, body: body.length ? body : undefined })
}

/** i18n 等非 get/verify 请求原样转发：它们由页面侧发起，补上真机静态头与会话票据才像 App 调用 */
async function sendRaw (target: string, method: 'GET' | 'POST', body: Buffer, type: string | undefined, dev: Dev, auth: Auth): Promise<Res> {
  const u = new URL(target)
  if (!PROXY_ALLOW.test(u.hostname)) throw new Error(`拒绝代理: ${u.hostname}`)
  const headers: Array<[string, string]> = [
    ['host', u.hostname],
    ['user-agent', ua(dev)],
    ['x-ss-dp', String(dev.aid)],
    ['x-vc-bdturing-sdk-version', '4.2.1.cn'],
    ['x-tt-request-tag', 'n=1;t=0;s=-1;p=0'],
    ['x-bd-kmsv', '1'],
    ['sdk-version', '2'],
    ['accept-encoding', 'gzip, deflate, br'],
  ]
  const cookie = auth.cookie()
  if (cookie) headers.push(['cookie', cookie])
  const token = auth.tokens['x-tt-token']
  if (token) headers.push(['x-tt-token', token])
  if (auth.mfaToken) headers.push(['x-tt-passport-mfa-token', auth.mfaToken])
  const csrf = auth.csrf()
  if (csrf) headers.push(['x-tt-passport-csrf-token', csrf])
  headers.push(['x-tt-passport-verify-portrait', auth.portrait])
  if (body.length) headers.push(['content-type', type ?? 'application/json; charset=utf-8'])
  return request({ url: target, method, headers, body: body.length ? body : undefined })
}

async function terminalQr (url: string): Promise<void> {
  try {
    const qr = await import('qrcode')
    log.info(`\n${await qr.toString(url, { type: 'terminal', small: true })}`)
  } catch {
    // 未安装 qrcode 或终端不支持时只留链接
  }
}

/** 起本地验证服务；返回的 Slide 在 verify 返回 200 时 wait() 立即完成 */
export async function serve (opts: SlideInput): Promise<Slide> {
  const { challenge, dev, ids, auth } = opts
  const port = opts.port ?? 8787
  const hits: string[] = []
  let settle!: (ok: boolean) => void
  let settled = false
  let result: Result = 'timeout'
  const verified = new Promise<boolean>(resolve => {
    settle = resolve
  })
  const timer = setTimeout(() => {
    log.warn(`等待滑块超时（${Math.round((opts.timeoutMs ?? 300_000) / 1000)}s）`)
    finish('timeout')
  }, opts.timeoutMs ?? 300_000)
  /** 只认第一次结果：verify 200、自动失败、超时、关闭可能并发触发 */
  const finish = (r: Result): void => {
    if (settled) return
    settled = true
    result = r
    clearTimeout(timer)
    settle(r === 'ok')
  }

  const handle = async (raw: string, method: 'GET' | 'POST', body: Buffer, type: string | undefined, res: http.ServerResponse, meta: { ip: string; ua: string }): Promise<void> => {
    hits.push(`${method} ${raw.slice(0, 200)}`)
    const path = new URL(raw).pathname
    const isCaptcha = /\/captcha\/(get|verify)$/i.test(path)
    const isVerify = /\/captcha\/verify$/i.test(path)
    // DY_H5=1：保持网页通道原样；DY_CAPTCHA=host/raw 用于排查改写范围（默认按真机全量改写）
    const h5Mode = h5()
    const cm = process.env.DY_CAPTCHA
    const mode = cm === 'host' || cm === 'raw' ? cm : 'app'
    const target = isCaptcha && !h5Mode
      ? mode === 'raw'
        ? raw
        : mode === 'host'
          ? `${appHost(challenge)}${raw.replace(/^https?:\/\/[^/]+/i, '')}`
          : rewrite(raw, dev, ids, challenge)
      : raw
    log.info(`${method} ${path} ip=${meta.ip} 通道=${h5Mode && isCaptcha ? 'h5' : mode} 头=${isCaptcha && !h5Mode ? (cm === 'full' ? 'full' : cm === 'plain' ? 'plain' : 'base') : '-'} ua=${meta.ua.slice(0, 120)}${body.length ? ` body=${body.length}B` : ''}`)
    try {
      const out = isCaptcha
        ? h5Mode
          ? await sendH5(target, method, body, type, meta.ua)
          : await sendCaptcha(target, method, isVerify ? withBdms(body) : body, type, dev, ids, auth, isVerify)
        : await sendRaw(target, method, body, type, dev, auth)
      res.writeHead(200, {
        'content-type': out.headers['content-type'] ?? 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
      })
      res.end(out.body)
      log.info(`${method} ${path} → ${out.status} logid=${out.headers['x-tt-logid'] ?? '-'} ${out.text.slice(0, 300)}`)
      if (!isVerify) return
      const code = Number((out.json as { code?: number } | undefined)?.code ?? -1)
      if (code === 200) {
        finish('ok')
        return
      }
      // 5014 是设备/网络的「环境判定」，与答案对错、冷却时长都无关：继续拖只会继续 5014
      if (out.text.includes('5014')) {
        log.warn('verify 5014（环境判定），需换网络后重试')
        finish('cool')
        return
      }
      log.warn(`verify 未通过 code=${code}`)
    } catch (e) {
      log.warn(`${method} ${path} 失败：${String(e)}`)
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ code: 502, message: String(e) }))
    }
  }

  const route = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const u = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`)
    const method = (req.method ?? 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET'
    const ip = String(req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? '-')
    const uaText = String(req.headers['user-agent'] ?? '-')
    if (method === 'GET' && (u.pathname === '/' || u.pathname === '/slide')) {
      // 决策由页面内联后 render() 交给 SDK，地址栏不塞参数：参考实现唯一成功过的配置就是这样，
      // 地址栏带参会让 SDK 的 get 使用决策里的旧上下文，与它随后下发的挑战错位
      log.info(`打开验证页 ip=${ip} ua=${uaText.slice(0, 160)}`)
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(page(challenge.decision, dev, ids))
      return
    }
    if (method === 'GET' && u.pathname === '/captcha-sdk.js' && SDK_FILE) {
      const body = readFileSync(SDK_FILE)
      res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8', 'content-length': String(body.length), 'cache-control': 'no-store' })
      res.end(body)
      return
    }
    if (u.pathname.startsWith('/captcha/')) {
      const body = await readBody(req)
      // 排查用：落一次 verify 的 URL 与 body，确认页面侧上报的环境是否仍是桌面形态
      if (process.env.DY_DUMP_GAP && method === 'POST') {
        const dir = process.env.DY_DUMP_GAP === '1' ? join(os.tmpdir(), 'dy-gap') : process.env.DY_DUMP_GAP
        mkdirSync(dir, { recursive: true })
        writeFileSync(join(dir, 'verify-body.txt'), `${decodeURIComponent(req.url ?? '')}\n\n${body.toString('utf8')}`)
      }
      await handle(`${PAGE_HOST}${req.url ?? ''}`, method, body, req.headers['content-type'], res, { ip, ua: uaText })
      return
    }
    // SDK 埋点收下即丢：转发会污染设备指纹
    if (/^\/(monitor_web|monitor_browser)\//.test(u.pathname)) {
      res.writeHead(204)
      res.end()
      return
    }
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('not found')
  }

  const server = http.createServer((req, res) => {
    void route(req, res).catch(e => {
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`server error: ${String(e)}`)
    })
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '0.0.0.0', () => resolve())
  })

  const url = `http://${lanIp()}:${port}/slide`
  log.info(`本地验证页已启动：${url}`)
  log.info(`手机需与电脑同网；打不开请放行 Node 入站端口 ${port}`)
  log.info(`票据 ${challenge.verifyTicket || '(无)'} 决策来源 ${String(challenge.decision['from'] ?? '-')}，拖动通过后自动继续登录`)
  await opts.onUrl?.(url)
  void terminalQr(url)
  // 页面环境必须伪装成 decision 声明的真机，否则 /captcha/get 直接 5014；
  // 自动方案失败不影响扫码手动拖，两边谁先过都算数
  log.info('已开始自动过滑块（本机 Edge/Chrome），失败仍可手机扫码手动拖')
  void solve({ url: `http://127.0.0.1:${port}/slide`, dev, done: () => settled })
    .then(step => {
      if (step) finish(step)
    })
    .catch(e => log.warn(`自动过滑块异常: ${String(e).slice(0, 160)}`))

  return {
    url,
    port,
    hits,
    wait: () => verified.finally(() => {
      settled = true
      clearTimeout(timer)
      server.close()
    }),
    result: () => result,
    close: () => {
      finish('closed')
      server.close()
    },
  }
}
