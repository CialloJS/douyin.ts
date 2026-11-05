/** 安全验证(验证中心)能力门面:登录轮询只用 parseDecision / verify / stringifyFields */
export { verify } from './server.js'
export { parseDecision } from './decision.js'
export { stringifyFields } from './json.js'
export type { Decision, Hooks, Outcome } from './types.js'
