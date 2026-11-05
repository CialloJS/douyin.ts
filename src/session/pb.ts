import protobuf from 'protobufjs'

/** 只用到 fromString：把 Long 收窄成最小接口，避免整个 Long 类型泄漏到业务层 */
export const LONG = protobuf.util.Long as unknown as { fromString (value: string): unknown }
