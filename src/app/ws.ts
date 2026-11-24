/** App 原生 Frontier 长连接：token 握手、30s 心跳、帧回执与指数退避重连 */
import WebSocket from 'ws'
import { SdkError } from '../error.js'
import { ackFrame, decodeFrame, type Frame } from './frame.js'
import { wsHeaders, wsUrl } from './link.js'
import type { RawData } from 'ws'
import type { Auth } from './auth.js'
import type { Dev, Ids } from './types.js'
import type { WsCloseEvent, WsReconnectEvent } from '../types.js'

export interface WsOpts {
  dev: Dev
  ids: Ids
  auth: Auth
  onFrame: (frame: Frame) => void
  onReconnecting?: (event: WsReconnectEvent) => void
  onClose?: (event: WsCloseEvent) => void
}

/** 30s 与握手 query 的 ping-interval 一致，过密会被服务端断开 */
const BEAT = 30_000

/** ws 可能把分片合并成数组，这里统一成连续字节 */
function bytes (data: RawData): Uint8Array {
  if (Buffer.isBuffer(data)) return data
  if (Array.isArray(data)) return Buffer.concat(data)
  return Buffer.from(data as ArrayBuffer)
}

function delay (attempt: number): number {
  return Math.min(30_000, 1_000 * 2 ** Math.max(0, attempt - 1))
}

/** 不打印日志：重连与关闭全部通过回调交给上层 */
export class Ws {
  private socket?: WebSocket
  private heartbeat?: ReturnType<typeof setInterval>
  private timer?: ReturnType<typeof setTimeout>
  private task?: Promise<void>
  private attempt = 0
  private stopped = true
  private opened = false

  constructor (private readonly opts: WsOpts) {}

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

  private open (): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(wsUrl(this.opts.dev, this.opts.ids), ['pbbp'], {
        headers: wsHeaders(this.opts.dev, this.opts.auth),
        handshakeTimeout: 30_000,
      })
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
      // open 后 error 仍可能触发：没有监听者时 ws 会抛进程级异常，这里只兜底
      socket.on('error', () => {})
      // 握手被拒时服务端在响应头里带诊断，先释放响应避免 socket 挂起
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
      })
      socket.on('message', (data: RawData) => {
        const frame = decodeFrame(bytes(data))
        if (!frame) return
        const ack = ackFrame(frame)
        if (ack && socket.readyState === WebSocket.OPEN) socket.send(ack)
        this.opts.onFrame(frame)
      })
      socket.on('close', (code, reason) => {
        this.stopBeat()
        if (this.socket === socket) delete this.socket
        const text = reason.toString()
        if (!isOpen) finish(new SdkError({ code, reason: text }))
        this.opts.onClose?.({ code, reason: text })
        if (!this.stopped && this.opened) this.schedule(code, text)
      })
    })
  }

  private schedule (code?: number, reason?: string): void {
    if (this.stopped || this.timer) return
    const attempt = ++this.attempt
    const delayMs = delay(attempt)
    const event: WsReconnectEvent = { attempt, delayMs }
    if (code != null) event.code = code
    if (reason) event.reason = reason
    this.opts.onReconnecting?.(event)
    this.timer = setTimeout(() => {
      delete this.timer
      if (this.stopped) return
      void this.open().catch(() => this.schedule())
    }, delayMs)
  }

  private beat (socket: WebSocket): void {
    this.heartbeat = setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) socket.ping()
    }, BEAT)
  }

  private release (task: Promise<void>): void {
    if (this.task === task) delete this.task
  }

  private stopBeat (): void {
    if (this.heartbeat) clearInterval(this.heartbeat)
    delete this.heartbeat
  }
}
