/** 实时接收：Android Frontier 长连接 + 推送分流（信号、编辑、通知、消息） */
import { AndroidFrontierWs } from '../live/ws.js'
import { Emitter } from '../session/emitter.js'
import { extractAndroidPushes, extractReactions, toInboundMessage, toReadEvent, toStatusEvent, toVoipCall } from '../message/recv.js'
import { extractAndroidNotices, noticeFromPush } from '../notice/notice.js'
import type { ImEventMap, ImOptions, NoticeEvent, PushMessage, RequestEvent } from '../types.js'

/** 系统消息类型：常由本机触发，需先于自发过滤分流为 notice */
const NOTICE_TYPES = new Set([1001, 50011])

export class Receiver extends Emitter<ImEventMap> {
  private readonly ws: AndroidFrontierWs
  private readonly selfUid: string
  private readonly selfMessage: boolean
  /** 高位信令先于自发过滤：发送者常为本机，但语义是对端/会话视角 */
  private readonly signals = new Map<number, (push: PushMessage) => void>([
    [50001, push => { const e = toStatusEvent(push); if (e) this.emit('status', e) }],
    [50013, push => { const e = toReadEvent(push); if (e) this.emit('read', e) }],
    [50018, push => { const e = toVoipCall(push); if (e) this.emit('voip', e) }],
  ])

  constructor (opts: ImOptions) {
    super()
    this.selfUid = opts.userId
    this.selfMessage = opts.selfMessage ?? false
    this.ws = new AndroidFrontierWs({
      userId: opts.userId,
      cookies: opts.cookies,
      callbacks: {
        onMessage: bytes => this.frame(bytes),
        onReconnecting: event => this.emit('reconnecting', event),
        onClose: event => this.emit('close', event),
      },
    })
  }

  get connected (): boolean {
    return this.ws.connected
  }

  async start (): Promise<void> {
    if (this.ws.connected) return
    await this.ws.connect()
  }

  stop (): void {
    this.ws.close()
  }

  /** 一帧内可能包含多类推送：先信号与通知，再普通消息 */
  private frame (bytes: Uint8Array): void {
    for (const notice of extractAndroidNotices(bytes)) this.route(notice)
    for (const reaction of extractReactions(bytes)) this.emit('notice', reaction)
    for (const push of extractAndroidPushes(bytes)) this.dispatch(push)
  }

  private dispatch (push: PushMessage): void {
    const signal = this.signals.get(push.messageType)
    if (signal) {
      signal(push)
      return
    }
    if (push.editCount != null || push.editInfo) {
      this.emit('message:edited', toInboundMessage(push))
      return
    }
    if (NOTICE_TYPES.has(push.messageType)) {
      const event = noticeFromPush(push)
      if (event) {
        this.route(event)
        return
      }
    }
    // 盖楼根消息（50002）正文为空，不作命令静默，直接进 message 分流
    if (push.messageType >= 50000 && !push.isThreadRoot) return
    if (push.senderUid === this.selfUid && !this.selfMessage) return
    const event = push.isThreadRoot ? undefined : noticeFromPush(push)
    if (event) {
      this.route(event)
      return
    }
    this.emit('message', toInboundMessage(push))
  }

  /** 好友申请/入群申请走 request，其余通知走 notice */
  private route (event: NoticeEvent | RequestEvent): void {
    if (event.type === 'friend.request' || event.type === 'group.join-request') this.emit('request', event)
    else this.emit('notice', event)
  }
}
