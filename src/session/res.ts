import { hdr } from './sign/const.js'

/**
 * Passport 二级验证决策头。与客户端一致：头存在就要先完成安全验证再重放原请求。
 */
export function verifyDecision (headers: Headers): string | undefined {
  return headers.get(hdr.verify) || undefined
}
