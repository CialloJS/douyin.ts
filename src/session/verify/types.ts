/** 安全验证(验证中心)能力:决策、Hooks、回填结果与本地验证页状态 */
import type { Http } from '../http.js'

/** 一次验证中心决策:raw 用于日志回放,decision 原样交给官方 SDK */
export interface Decision {
  raw: string
  decision: Record<string, unknown>
  secondary: boolean
}

export interface Hooks {
  /** 验证页就绪后回调(把链接推给用户在浏览器打开) */
  onUrl?: (url: string) => void
  /** SecondVerify SDK aid(桌面 IM 339757 / 网页登录 6383);缺省用决策 aid,再缺省桌面 */
  aid?: number
  /** 验证请求 host(SDK 相对路径解析基准与 Referer);缺省按 aid 推断 */
  host?: string
  /** 默认 5 分钟 */
  timeoutMs?: number
}

/** 验证完成结果:fp 回填 query,fields 回填 body */
export interface Outcome {
  fp?: string
  fields: Record<string, unknown>
}

/** 代理请求结果:保留原始文本供页面侧 SDK 自行解析 */
export interface Raw {
  ok: boolean
  status: number
  headers: Headers
  text: string
}

interface Base {
  config: Record<string, unknown>
  fp: string
  deviceId: string
  aid: number
  host: string
  appName: string
}

/**
 * 两种组件形态用联合类型表达,让页面侧按 mode 读取对应字段时无需判空:
 * verify-center 用脚本地址列表 + captcha 业务参数,second-verify 用单个脚本地址或本地内置 SDK。
 */
export type Prepared =
  | (Base & { mode: 'verify-center'; scripts: string[]; options: Record<string, unknown> })
  | (Base & { mode: 'second-verify'; script?: string })

export interface State {
  http: Http
  prep: Prepared
  react: Buffer
  reactDom: Buffer
  token: string
  finish: (error?: Error, outcome?: Outcome) => void
}
