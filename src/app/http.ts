/** 裸 HTTPS 请求：保留头顺序与多条 set-cookie，响应按 content-encoding 解压 */
import * as https from 'node:https'
import { createLog } from '../session/log.js'
import { decompress } from './codec.js'

const debug = createLog({ tag: 'http' })

/** APP_DEBUG=1/true 时输出原始报文；按次读取便于运行时开关 */
function trace (): boolean {
  const v = process.env.APP_DEBUG
  return v === '1' || v === 'true'
}

/** 二进制载荷转 hex，文本截断避免刷爆终端 */
function dump (buf?: Buffer): string {
  if (!buf?.length) return '-'
  const text = buf.toString('utf8')
  if (text.includes('\uFFFD')) return `hex(${buf.length}) ${buf.subarray(0, 512).toString('hex')}${buf.length > 512 ? '…' : ''}`
  return text.length > 8000 ? `${text.slice(0, 8000)}…(${text.length})` : text
}

export interface Res {
  status: number
  /** 头名统一小写；同名合并为逗号串 */
  headers: Record<string, string>
  setCookie: string[]
  body: Buffer
  text: string
  json: unknown
}

export interface Req {
  url: string
  method?: 'GET' | 'POST'
  /** 保持顺序的原始头（同名可重复） */
  headers?: Array<[string, string]>
  body?: Buffer
  timeoutMs?: number
  /** 默认按 content-encoding 解压 */
  autoDecompress?: boolean
}

export function request (opts: Req): Promise<Res> {
  const u = new URL(opts.url)
  const method = opts.method ?? 'GET'
  const headers: Record<string, string | string[]> = {}
  const seen = new Set<string>()
  for (const [k, v] of opts.headers ?? []) {
    const lk = k.toLowerCase()
    if (seen.has(lk)) {
      const cur = headers[lk]
      headers[lk] = Array.isArray(cur) ? [...cur, v] : [String(cur), v]
    } else {
      headers[lk] = v
      seen.add(lk)
    }
  }
  if (opts.body) headers['content-length'] = String(opts.body.length)

  const at = Date.now()
  if (trace()) {
    const head = (opts.headers ?? []).map(([k, v]) => `  ${k}: ${v}`).join('\n')
    debug.info(`→ ${method} ${opts.url}\n${head}\n\n${dump(opts.body)}`)
  }

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method,
        headers,
        timeout: opts.timeoutMs ?? 30000,
      },
      res => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          const raw = Buffer.concat(chunks)
          const hdrs: Record<string, string> = {}
          const setCookie: string[] = []
          for (const [k, v] of Object.entries(res.headers)) {
            if (v === undefined) continue
            const lk = k.toLowerCase()
            if (lk === 'set-cookie') setCookie.push(...(Array.isArray(v) ? v : [v]))
            hdrs[lk] = Array.isArray(v) ? v.join(', ') : String(v)
          }
          let body: Buffer = raw
          if (opts.autoDecompress !== false) {
            try {
              body = decompress(raw, hdrs['content-encoding'] ?? '')
            } catch {
              body = raw
            }
          }
          const text = body.toString('utf8')
          let json: unknown
          try {
            json = JSON.parse(text)
          } catch {
            json = undefined
          }
          if (trace()) {
            const head = Object.entries(hdrs).map(([k, v]) => `  ${k}: ${v}`).join('\n')
            debug.info(`← ${res.statusCode ?? 0} ${method} ${u.pathname}${u.search} (${Date.now() - at}ms)\n${head}\n\n${dump(body)}`)
          }
          resolve({ status: res.statusCode ?? 0, headers: hdrs, setCookie, body, text, json })
        })
      },
    )
    req.on('timeout', () => req.destroy(new Error('请求超时')))
    req.on('error', error => {
      if (trace()) debug.error(`✗ ${method} ${opts.url} (${Date.now() - at}ms) ${error.message}`)
      reject(error)
    })
    if (opts.body) req.write(opts.body)
    req.end()
  })
}
