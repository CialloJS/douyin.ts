/**
 * SDK 只把错误来源原样交回，不做字段重命名、不拼描述、不映射错误码。
 * 上游失败 → data 是上游响应体；前置校验 → data 是失败字段；网络失败 → data 是原生错误。
 */
export class SdkError<T = unknown> extends Error {
  override readonly name = 'SdkError'

  constructor (readonly data: T, options?: ErrorOptions) {
    // message 保持常量：动态内容只可能在 data 里，避免调用方解析字符串
    super('sdk', options)
  }
}

export function err (data: unknown, options?: ErrorOptions): never {
  throw new SdkError(data, options)
}

export function isErr (value: unknown): value is SdkError {
  return value instanceof SdkError
}
