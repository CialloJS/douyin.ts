/** HTTP 通道公共类型：统一响应形态与构造选项 */
import type { Log } from '../types.js'

/** data 与 text 并存：JSON 调用方取 data，HTML/protobuf 调用方取 text */
export interface Res<T = unknown> {
  ok: boolean
  status: number
  headers: Headers
  data: T
  text: string
}

export interface ResBytes<T = Uint8Array> {
  ok: boolean
  status: number
  headers: Headers
  data: T
}

export interface HttpOpts {
  /** 浏览器复制的 Cookie 或上一轮会话 */
  cookie?: string
  /** 当前账号 uid，发消息/收件箱/上传链路使用 */
  userId?: string
  userAgent?: string
  /** 默认请求超时毫秒；init.signal 显式传入时优先生效 */
  timeout?: number
  log?: Log
}
