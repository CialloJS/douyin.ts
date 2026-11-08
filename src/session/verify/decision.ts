/** 决策解析:按官方客户端优先级挑选验证中心下发的配置 */
import { vc } from '../login/codes.js'
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
  // 主决策优先于二次决策;两层嵌套都能出现,顺序对齐客户端探测顺序。
  // 只认布尔真值:主决策可能是 false/0,不能让假值遮住真实的二次决策
  const selected = candidates.find(([value]) => Boolean(value))
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
  // 无显式 conf 就是没有验证决策:错误码/captcha 字段不能被客户端自行拼成决策,
  // 否则会凭空拉起验证页,重复验证直接把确认轮打成频控
  return undefined
}

/** conf 既可能是对象 JSON,也可能直接是字符串,统一包成 verify_data */
function parseConf (value: string): Record<string, unknown> {
  const parsed = tryParse(value)
  return asRecord(parsed) ?? { verify_data: parsed }
}
