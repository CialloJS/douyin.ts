/** JSON 与字段编码:所有非结构化响应都先按 unknown 收窄,避免 any 泄漏 */

export function asRecord (value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

export function asStringRecord (value: unknown): Record<string, string> {
  const record = asRecord(value)
  if (!record) return {}
  return Object.fromEntries(
    Object.entries(record)
      .filter(([, item]) => item != null)
      .map(([key, item]) => [key, String(item)]),
  )
}

export function tryParse (value: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    return value
  }
}

/** 嵌入页面的 JSON 必须转义 <>&,否则字符串里的 </script> 会截断脚本块 */
export function safeJson (value: unknown): string {
  return JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/g,
    char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`,
  )
}

export function escapeHtml (value: string): string {
  return value.replace(
    /[&<>"']/g,
    char =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      })[char]!,
  )
}

/** Passport 字段编码:字符串原样,数字/布尔转字符串,对象 JSON 序列化 */
export function encodeField (value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

/** 验证结果字段回填 check_qrconnect body 时统一转为字符串 */
export function stringifyFields (fields: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(fields)
      .filter(([, value]) => value != null)
      .map(([key, value]) => [key, encodeField(value)]),
  )
}
