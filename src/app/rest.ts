/** App 业务 JSON 接口：复用 IM 签名链路，按抓包选择明文/zstd/form 编码 */
import type { Enc, Im } from './im.js'

export interface RestOpts {
  /** 业务接口分散在 core/platform/normal 等域 */
  host?: string
  method?: 'GET' | 'POST'
  /** 默认按 body 推断 json/zstd-json */
  enc?: Enc
  query?: Record<string, string | number>
  /** 对象按 JSON 序列化；已拼接好的 form 串直接传字符串 */
  body?: Record<string, unknown> | string
}

/** form 体里数组按 JSON 串写入，与真机 show_group_list=[...] 的形态一致 */
function form (body: Record<string, unknown>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(body)) {
    if (v === undefined) continue
    q.append(k, typeof v === 'string' ? v : JSON.stringify(v))
  }
  return q.toString()
}

export async function rest<T = Record<string, unknown>> (im: Im, path: string, opts: RestOpts = {}): Promise<T> {
  const enc = opts.enc ?? (opts.body === undefined ? 'none' : 'json')
  const body = opts.body === undefined
    ? undefined
    : typeof opts.body === 'string'
      ? opts.body
      : enc === 'form' || enc === 'zstd-form' ? form(opts.body) : JSON.stringify(opts.body)
  const res = await im.call({
    path,
    host: opts.host,
    method: opts.method ?? (body === undefined ? 'GET' : 'POST'),
    enc,
    query: opts.query,
    body,
  })
  if (res.json !== undefined) return res.json as T
  const text = res.text.trim()
  if (!text) return {} as T
  throw new Error(`${path} 非 JSON 响应 status=${res.status}`)
}

/** 常用业务 host，抓包中同一 path 可能在多个域下命中 */
export const DOMAIN = {
  core: 'api5-core-jj.amemv.com',
  social: 'api5-social-m-jj.amemv.com',
  socialLf: 'api5-social-m-lf.amemv.com',
  normal: 'api5-normal-lf.amemv.com',
  normalM: 'api5-normal-m-jj.amemv.com',
  normal3: 'api3-normal-c.amemv.com',
  platform: 'api5-platform-lf.amemv.com',
  platformM: 'api5-platform-m-jj.amemv.com',
} as const
