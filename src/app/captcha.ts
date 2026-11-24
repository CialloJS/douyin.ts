/** 1105 滑块挑战解析：决策整包在响应头 bdturing-verify，body 里是同一份 JSON */
import type { Res } from './http.js'

export interface Challenge {
  /** passport 会话票据，重试时回带 */
  verifyTicket: string
  /** bdturing 决策（含加密 detail，只有 App SDK 能解） */
  decision: Record<string, unknown>
  /** bdturing-verify 原文：外部验证页必须用它复刻本次决策，重新取会错位 */
  raw: string
  /** x-vc-bdturing-parameters：bdturing 采集参数 */
  params: string
  subtype: string
  verifyEvent: string
  logId: string
  at: number
}

function obj (v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' ? (v as Record<string, unknown>) : {}
}

/** 优先响应头，其次 body 的 verify_center_decision_conf */
export function read (res?: Res): Challenge | undefined {
  if (!res) return undefined
  const data = obj(obj(res.json)['data'])
  let decision: Record<string, unknown> = {}
  const header = res.headers['bdturing-verify']
  if (header) {
    try {
      decision = obj(JSON.parse(header))
    } catch {
      // 头不是 JSON 就用 body 兜底
    }
  }
  if (Object.keys(decision).length === 0) {
    const conf = data['verify_center_decision_conf']
    if (typeof conf === 'string') {
      try {
        decision = obj(JSON.parse(conf))
      } catch {
        return undefined
      }
    }
  }
  const verifyTicket = String(decision['verify_ticket'] ?? data['verify_ticket'] ?? '')
  if (!verifyTicket && !decision['detail']) return undefined
  return {
    verifyTicket,
    decision,
    raw: header ?? JSON.stringify(decision),
    params: res.headers['x-vc-bdturing-parameters'] ?? '',
    subtype: String(decision['subtype'] ?? ''),
    verifyEvent: String(decision['verify_event'] ?? ''),
    logId: String(decision['log_id'] ?? res.headers['x-tt-logid'] ?? ''),
    at: Date.now(),
  }
}
