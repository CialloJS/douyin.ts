/** 验证页本地路由:页面/静态资源/代理接口用三张注册表分发,不写方法 if 链 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import { err, SdkError } from '../../error.js'
import { im } from '../sign/const.js'
import type { State } from './types.js'
import { asRecord, asStringRecord, tryParse } from './json.js'
import { allowHost, cleanHeaders, requestRaw } from './proxy.js'
import { page } from './page.js'
import { loadSdk } from './sdk.js'

/** 页面侧只允许这些方法,避免被拿来做任意协议探测 */
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])

/** 页面轨迹按内容节流:曾出现 /api/log 自激循环导致终端卡顿 */
const THROTTLE = 600
const MAXLINES = 2000
const logs = new Map<string, number>()

type Page = (state: State) => string
type Script = (state: State) => Buffer | Promise<Buffer>
type Api = (request: IncomingMessage, response: ServerResponse, state: State) => Promise<void>

const pages: Record<string, Page> = {
  '/': state => page(state.prep, state.token),
}

const scripts: Record<string, Script> = {
  '/react.js': state => state.react,
  '/react-dom.js': state => state.reactDom,
  '/second-verify-sdk.js': () => loadSdk(),
}

const apis: Record<string, Api> = {
  '/api/request': async (request, response, state) => {
    const payload = await readJsonBody(request)
    // SDK 相对路径以登录场景 host 为基准(web 6383 → www.douyin.com / 桌面 → imdesktop)
    const target = resolveUrl(payload['url'], payload['baseURL'] ?? state.prep.host)
    allowHost(target)
    const method = String(payload['method'] ?? 'GET').toUpperCase()
    if (!METHODS.has(method)) err({ method })
    const body = typeof payload['body'] === 'string' ? payload['body'] : undefined
    const result = await requestRaw(state.http, target.toString(), {
      method,
      headers: cleanHeaders(asStringRecord(payload['headers'])),
      ...(body !== undefined && method !== 'GET' && method !== 'HEAD' ? { body } : {}),
    })
    sendJson(response, 200, {
      data: tryParse(result.text),
      rawText: result.text,
      status: result.status,
      statusText: result.ok ? 'OK' : 'ERROR',
      headers: Object.fromEntries(
        [...result.headers.entries()].filter(([key]) => key.toLowerCase() !== 'set-cookie'),
      ),
    })
  },
  '/api/complete': async (request, response, state) => {
    const payload = await readJsonBody(request)
    const result = asRecord(payload['result'])
    const fields = asRecord(result?.['fields'] ?? result) ?? {}
    const fp = String(result?.['fp'] ?? '') || state.prep.fp
    sendJson(response, 200, { ok: true })
    state.finish(undefined, { fp, fields })
  },
  '/api/log': async (request, response, state) => {
    const payload = await readJsonBody(request)
    const line = String(payload['line'] ?? '').slice(0, 500)
    const now = Date.now()
    const last = logs.get(line)
    if (last === undefined || now - last > THROTTLE) {
      logs.set(line, now)
      if (logs.size > MAXLINES) logs.clear()
      state.http.log.info(`verify:page ${line}`)
    }
    sendJson(response, 200, { ok: true })
  },
  '/api/cancel': async (_request, response, state) => {
    sendJson(response, 200, { ok: true })
    state.finish(new SdkError({ cancel: true }))
  },
}

export async function route (
  request: IncomingMessage,
  response: ServerResponse,
  state: State,
): Promise<void> {
  const url = new URL(request.url ?? '/', 'http://127.0.0.1')
  if (url.searchParams.get('token') !== state.token) {
    sendJson(response, 403, { error: '登录验证会话无效' })
    return
  }
  if (request.method === 'GET') {
    const html = pages[url.pathname]
    if (html) {
      sendHtml(response, html(state))
      return
    }
    const script = scripts[url.pathname]
    if (script) {
      sendScript(response, await script(state))
      return
    }
  }
  if (request.method === 'POST') {
    const api = apis[url.pathname]
    if (api) {
      await api(request, response, state)
      return
    }
  }
  response.writeHead(404)
  response.end('Not Found')
}

function resolveUrl (urlValue: unknown, baseValue: unknown): URL {
  return new URL(String(urlValue ?? ''), String(baseValue ?? im.origin))
}

async function readJsonBody (request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let length = 0
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    length += buffer.length
    if (length > 1_048_576) err({ length })
    chunks.push(buffer)
  }
  const text = Buffer.concat(chunks).toString('utf8') || '{}'
  return JSON.parse(text) as Record<string, unknown>
}

export function sendJson (response: ServerResponse, status: number, data: unknown): void {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  response.end(JSON.stringify(data))
}

function sendHtml (response: ServerResponse, html: string): void {
  response.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
  })
  response.end(html)
}

function sendScript (response: ServerResponse, script: Buffer): void {
  response.writeHead(200, {
    'content-type': 'text/javascript; charset=utf-8',
    'cache-control': 'public, max-age=3600',
  })
  response.end(script)
}
