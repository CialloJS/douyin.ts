/** 验证中心决策:风控/滑块等非 0 error_code 下发的本地安全验证 */
import { parseDecision } from '../verify/decision.js'
import { stringifyFields } from '../verify/json.js'
import { verify } from '../verify/server.js'
import { passport } from '../sign/const.js'
import type { Http } from '../http.js'
import type { CheckData, LoginOpts } from './types.js'

export interface CenterResult {
  fields: Record<string, string>
  fp?: string
}

/** 有决策则拉起本地验证页并把结果字段交回轮询;无决策返回 undefined */
export async function verifyCenter (
  http: Http,
  data: CheckData,
  decision: string | undefined,
  opts: LoginOpts,
): Promise<CenterResult | undefined> {
  const center = parseDecision(data, decision)
  if (!center) return
  // aid 显式用桌面 IM 339757：验证页按 imdesktop 场景渲染
  const outcome = await verify(http, center, { onUrl: opts.onVerifyUrl, aid: Number(passport.aid) })
  return { fields: stringifyFields(outcome.fields), fp: outcome.fp }
}
