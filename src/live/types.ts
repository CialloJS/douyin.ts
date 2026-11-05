/** IM 协议底层公共类型：编解码入参/响应与 WS 连接选项 */
import type { WsCloseEvent, WsReconnectEvent } from './ws.js'

export interface EncodeRequestOptions {
  token: string
  cmd: number
  inboxType?: number
  body?: Record<string, unknown>
  sequenceId?: number
  authType?: number
  /** device_id（浏览器发消息为空字符串） */
  deviceId?: string
  /** 覆盖 device_platform */
  devicePlatform?: string
  /** 覆盖 headers */
  headers?: Record<string, string>
  sdkVersion?: string
  buildNumber?: string
  refer?: number
  versionCode?: string
  biz?: string
  access?: string
}

export interface DecodedResponse {
  cmd: number
  sequenceId: number
  statusCode: number
  errorDesc: string
  inboxType: number
  body: Record<string, unknown> | null
  logId: string
}

export interface AndroidFrontierWsOptions {
  userId: string
  cookies: string
  /** 事件回调 */
  callbacks?: AndroidFrontierWsCallbacks
}

export interface AndroidFrontierWsCallbacks {
  onOpen?: () => void
  /** 二进制帧分发：原始字节交给业务层解析 */
  onMessage?: (bytes: Uint8Array) => void
  onClose?: (event: WsCloseEvent) => void
  onReconnecting?: (event: WsReconnectEvent) => void
  onError?: (error: Error) => void
}
