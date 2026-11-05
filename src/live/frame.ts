import { frontierSign, WS_SIGN_CMDS } from '../session/sign/frontier.js'
import { ANDROID_SDK_VERSION, ANDROID_UA, android, androidHeaders } from './profile.js'
import { fieldBytes, fieldStringValue, fieldVarint, kv } from './wire.js'

export interface Cmd411FrameOptions {
  /** 账号 uid（作 envelope device_id） */
  userId: string
  conversationId: string
  conversationShortId: string
  conversationType: number
  /** true=正在输入(3)，false=清除输入(4) */
  typing: boolean
}

let seqCount = 0

/** 组一条 WS cmd=411 输入状态帧：f1=411、f8=SendInputStatusRequest（三层结构与 Android Frontier WS 帧一致） */
export function buildCmd411Frame (options: Cmd411FrameOptions): Uint8Array {
  const seq = ++seqCount
  const ms = Date.now()

  const body = Buffer.concat([
    fieldStringValue(1, options.conversationId),
    fieldVarint(2, options.conversationType),
    fieldVarint(3, BigInt(options.conversationShortId || '0')),
    // InputStatus 枚举：3 正在输入 / 4 清除输入（与接收侧 input_status=1/0 不同）
    fieldVarint(4, options.typing ? 3 : 4),
  ])

  const parts: Buffer[] = [
    fieldVarint(1, 411),
    fieldVarint(2, seq),
    fieldStringValue(3, ANDROID_SDK_VERSION),
    fieldVarint(5, 1),
    fieldVarint(6, 0),
    fieldStringValue(7, android.buildNumber),
    fieldBytes(8, body),
    fieldStringValue(9, options.userId),
    fieldStringValue(10, android.channel),
    fieldStringValue(11, 'android'),
    fieldStringValue(12, android.deviceType),
    fieldStringValue(13, android.osVersion),
    fieldStringValue(14, android.versionCode),
  ]
  for (const [key, value] of androidHeaders(options.userId)) parts.push(kv(15, key, value))
  parts.push(
    fieldVarint(18, 0),
    fieldStringValue(21, android.biz),
    fieldStringValue(22, android.access),
  )
  const inner = Buffer.concat(parts)

  const headers: [string, string][] = [
    ['msg_type', 'cmd411'], ['seq_id', String(seq)], ['cmd', '411'], ['is-retry', '0'], ['flow-tag', 'new'],
  ]
  if (WS_SIGN_CMDS.has(411)) {
    for (const sign of frontierSign(inner, { userAgent: ANDROID_UA })) headers.push([sign.key, sign.value])
  }

  const frame: Buffer[] = [
    fieldVarint(1, seq),
    fieldVarint(2, ms),
    fieldVarint(3, 5),
    fieldVarint(4, 1),
  ]
  for (const [key, value] of headers) frame.push(kv(5, key, value))
  frame.push(fieldStringValue(6, 'pb'), fieldStringValue(7, 'pb'), fieldBytes(8, inner))
  return Buffer.concat(frame)
}
