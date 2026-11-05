/** 决策解析:按官方客户端优先级挑选验证中心下发的配置 */
import { ec, vc } from '../login/codes.js'
import type { CheckData } from '../login/types.js'
import type { Decision } from './types.js'
import { asRecord, tryParse } from './json.js'

/**
 * 响应头决策优先于响应体:真实客户端把该头原样交给 SecondVerify SDK,
 * 头存在即代表必须二次验证,body 里的 conf 只是补充。
 */
export function parseDecision (data: CheckData, header?: string): Decision | undefined {
  if (typeof header === 'string' && header.length > 0) {
    const record = asRecord(tryParse(header))
    if (record) {
      return {
        raw: JSON.stringify(record),
        decision: { ...record, verification_level: vc.level },
        secondary: true,
      }
    }
    return {
      raw: header,
      decision: { verify_data: header, verification_level: vc.level },
      secondary: true,
    }
  }
  const source = data as unknown as Record<string, unknown>
  const nested = asRecord(source['data'])
  // 主决策优先于二次决策;两层嵌套都能出现,顺序对齐客户端探测顺序
  const candidates: ReadonlyArray<readonly [unknown, boolean]> = [
    [nested?.['verify_center_decision_conf'], false],
    [nested?.['verify_center_secondary_decision_conf'], true],
    [source['verify_center_decision_conf'], false],
    [source['verify_center_secondary_decision_conf'], true],
  ]
  const selected = candidates.find(([value]) => value != null && value !== '')
  const rawValue = selected?.[0]
  const secondary = selected?.[1] === true
  const record = asRecord(rawValue)
  if (record) {
    return {
      raw: JSON.stringify(record),
      decision: { ...record, ...(secondary ? { verification_level: vc.level } : {}) },
      secondary,
    }
  }
  if (typeof rawValue === 'string' && rawValue.length > 0) {
    return {
      raw: rawValue,
      decision: { ...parseConf(rawValue), ...(secondary ? { verification_level: vc.level } : {}) },
      secondary,
    }
  }
  // 无 conf 时风控码与 captcha 字段是唯一线索,否则本次登录无需验证
  const errorCode = Number(source['error_code'] ?? 0)
  const captcha = source['captcha']
  const hasCaptcha = captcha != null && captcha !== ''
  if (errorCode !== ec.risk && !hasCaptcha) return undefined
  const fallback: Record<string, unknown> = {
    verify_from: vc.captcha,
    ...(hasCaptcha ? { captcha } : {}),
    ...(source['verify_ticket'] != null ? { verify_ticket: source['verify_ticket'] } : {}),
  }
  return { raw: JSON.stringify(fallback), decision: fallback, secondary: false }
}

/** conf 既可能是对象 JSON,也可能直接是字符串,统一包成 verify_data */
function parseConf (value: string): Record<string, unknown> {
  const parsed = tryParse(value)
  return asRecord(parsed) ?? { verify_data: parsed }
}
