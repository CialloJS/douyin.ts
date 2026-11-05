import { protectBigInt } from '../notice/notice.js'

/** 推送 content 偶发非 JSON 变体，解析失败交给调用方按缺省处理；protect 时保 16+ 位数字精度 */
export function parseContent (text: string, protect = false): Record<string, unknown> | undefined {
  try {
    return JSON.parse(protect ? protectBigInt(text) : text) as Record<string, unknown>
  } catch {
    return undefined
  }
}

export const str = (value: unknown): string => (value == null ? '' : String(value))

export const num = (value: unknown): number => (value == null ? 0 : Number(value))
