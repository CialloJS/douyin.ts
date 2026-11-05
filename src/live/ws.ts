import WebSocket from 'ws'
import { SdkError } from '../error.js'
import { reconnectDelay, toBytes, wsHeaders, wsUrl } from './link.js'
import type { RawData } from 'ws'
import type { AndroidFrontierWsOptions } from './types.js'

export interface WsReconnectEvent {
  attempt: number
  delayMs: number
  code?: number
  reason?: string
}

export interface WsCloseEvent {
  code?: number
  reason?: string
}

/** 结果已定后关闭连接：CONNECTING 只能 terminate，否则是等待 socket 挂起 */
function shut (socket: WebSocket): void {
  try {
    if (socket.readyState === WebSocket.OPEN) socket.close()
    else if (socket.readyState === WebSocket.CONNECTING) socket.terminate()
  } catch {
    // 连接已断开，忽略清理失败
  }
}

/**
 * Cookie 鉴权 Android Frontier WS：连接 / 15s 心跳 / 指数退避重连 / 帧分发。
 * 不打印日志：正常重连等事件全部通过回调通知，由上层决定记录策略。
 */
export class AndroidFrontierWs {
  private socket?: WebSocket
  private heartbeat?: ReturnType<typeof setInterval>
  private timer?: ReturnType<typeof setTimeout>
  private task?: Promise<void>
  private attempt = 0
  private stopped = true
  private opened = false

  constructor (private readonly options: AndroidFrontierWsOptions) {}

  get connected (): boolean {
    return this.socket?.readyState === WebSocket.OPEN
  }

  connect (): Promise<void> {
    if (this.connected) return Promise.resolve()
    if (this.task) return this.task
    this.stopped = false
    const task = this.open()
    this.task = task
    void task.then(() => this.release(task), () => this.release(task))
    return task
  }

  close (): void {
    this.stopped = true
    this.opened = false
    this.attempt = 0
    if (this.timer) clearTimeout(this.timer)
    delete this.timer
    this.stopBeat()
    this.socket?.close()
    delete this.socket
  }

  /**
   * 一次性连接发送帧并等待响应提取（Android cmd=100 直发）。
   * 返回 undefined 表示超时/连接失败/未匹配到响应。
   */
  async sendOnce<T> (
    frame: Uint8Array,
    extract: (payload: Uint8Array) => T | undefined,
    ackTimeoutMs = 4_000,
  ): Promise<T | undefined> {
    return new Promise(resolve => {
      const socket = this.connectSocket()
      let done = false
      let ackTimer: ReturnType<typeof setTimeout> | undefined
      const finish = (result: T | undefined): void => {
        if (done) return
        done = true
        if (ackTimer) clearTimeout(ackTimer)
        clearTimeout(connectTimer)
        socket.off('message', onMessage)
        shut(socket)
        resolve(result)
      }
      const onMessage = (data: RawData): void => {
        const result = extract(toBytes(data))
        if (result !== undefined) finish(result)
      }
      socket.once('open', () => {
        ackTimer = setTimeout(() => finish(undefined), ackTimeoutMs)
        socket.send(frame, error => {
          if (error) finish(undefined)
        })
      })
      socket.on('message', onMessage)
      socket.once('close', () => finish(undefined))
      socket.once('error', () => finish(undefined))
      const connectTimer = setTimeout(() => finish(undefined), 30_000)
    })
  }

  /**
   * 一次性连接发送帧即关（无回执语义，411 输入状态用）。
   * 返回 true 表示帧已成功写入连接；false 表示连接或发送失败。
   */
  async sendFireOnce (frame: Uint8Array): Promise<boolean> {
    return new Promise(resolve => {
      const socket = this.connectSocket()
      let done = false
      const finish = (ok: boolean): void => {
        if (done) return
        done = true
        clearTimeout(guard)
        shut(socket)
        resolve(ok)
      }
      // open 后若 send 回调未触发，靠兜底计时器放行
      const guard = setTimeout(() => finish(false), 15_000)
      socket.once('open', () => {
        socket.send(frame, error => finish(!error))
      })
      socket.once('close', () => finish(false))
      socket.once('error', () => finish(false))
    })
  }

  private open (): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = this.connectSocket()
      this.socket = socket
      let done = false
      let isOpen = false
      const finish = (error?: Error): void => {
        if (done) return
        done = true
        if (error) reject(error)
        else resolve()
      }
      socket.once('error', finish)
      // 握手被拒时服务端在响应头里带诊断（如 handshake-msg），先释放响应避免 socket 挂起
      socket.once('unexpected-response', (_req, res) => {
        res.resume()
      })
      socket.once('open', () => {
        if (this.stopped) {
          socket.close()
          finish()
          return
        }
        isOpen = true
        socket.off('error', finish)
        finish()
        this.attempt = 0
        this.opened = true
        this.beat(socket)
        this.options.callbacks?.onOpen?.()
      })
      socket.on('message', (data: RawData) => {
        this.options.callbacks?.onMessage?.(toBytes(data))
      })
      socket.on('close', (code, reason) => {
        this.stopBeat()
        if (this.socket === socket) delete this.socket
        const text = reason.toString()
        if (!isOpen) finish(new SdkError({ code, reason: text }))
        this.options.callbacks?.onClose?.({ code, reason: text })
        if (!this.stopped && this.opened) this.schedule(code, text)
      })
      socket.on('error', error => {
        this.options.callbacks?.onError?.(error)
      })
    })
  }

  private connectSocket (): WebSocket {
    return new WebSocket(wsUrl(this.options.userId), ['pbbp2'], {
      headers: wsHeaders(this.options.cookies),
      handshakeTimeout: 30_000,
    })
  }

  private beat (socket: WebSocket): void {
    this.heartbeat = setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) socket.ping()
    }, 15_000)
  }

  private schedule (code?: number, reason?: string): void {
    if (this.stopped || this.timer) return
    const attempt = ++this.attempt
    const delayMs = reconnectDelay(attempt)
    const event: WsReconnectEvent = { attempt, delayMs }
    if (code != null) event.code = code
    if (reason) event.reason = reason
    this.options.callbacks?.onReconnecting?.(event)
    this.timer = setTimeout(() => {
      delete this.timer
      if (this.stopped) return
      void this.open().catch(() => this.schedule())
    }, delayMs)
  }

  private release (task: Promise<void>): void {
    if (this.task === task) delete this.task
  }

  private stopBeat (): void {
    if (this.heartbeat) clearInterval(this.heartbeat)
    delete this.heartbeat
  }
}
