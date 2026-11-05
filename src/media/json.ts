/** 服务端字段类型不稳定，先宽松读一层 record 再逐字段收窄 */
export function asRecord (value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {}
}
