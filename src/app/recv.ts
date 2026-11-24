/** App 推送分发：只处理 IM 服务帧，事件语义与 web 通道一致，但传输完全独立 */
import { Emitter } from '../session/emitter.js'
import { extractAndroidPushes, extractReactions, toInboundMessage, toReadEvent, toStatusEvent, toVoipCall } from '../message/recv.js'
import { extractAndroidNotices, noticeFromPush } from '../notice/notice.js'
import { lz4 } from './codec.js'
import { Ws } from './ws.js'
import type { Frame } from './frame.js'
import type { Auth } from './auth.js'
import type { Dev, Ids } from './types.js'
import type { ImEventMap, Log, NoticeEvent, PushMessage, RequestEvent } from '../types.js'

/** IM SDK 只认这两个 service；33554856 是 App 侧的扩展通道 */
const SERVICES = new Set([5, 33554856])
/** 系统消息类型：常由本机触发，需先于自发过滤分流为 notice */
const NOTICE_TYPES = new Set([1001, 50011])

export interface RecvOpts {
  dev: Dev
  ids: Ids
  auth: Auth
  log: Log
  selfMessage?: boolean
}

export class Recv extends Emitter<ImEventMap> {
  private readonly ws: Ws
  private readonly auth: Auth
  private readonly log: Log
  private readonly selfMessage: boolean
  /** 高位信令先于自发过滤：发送者常为本机，但语义是对端/会话视角 */
  private readonly signals = new Map<number, (push: PushMessage) => void>([
    [50001, push => { const e = toStatusEvent(push); if (e) this.emit('status', e) }],
    [50013, push => { const e = toReadEvent(push); if (e) this.emit('read', e) }],
    [50018, push => { const e = toVoipCall(push); if (e) this.emit('voip', e) }],
  ])

  constructor (opts: RecvOpts) {
    super()
    this.auth = opts.auth
    this.log = opts.log
    this.selfMessage = opts.selfMessage ?? false
    this.ws = new Ws({
      dev: opts.dev,
      ids: opts.ids,
      auth: opts.auth,
      onFrame: frame => this.frame(frame),
      onReconnecting: event => this.emit('reconnecting', event),
      onClose: event => this.emit('close', event),
    })
  }

  get connected (): boolean {
    return this.ws.connected
  }

  start (): Promise<void> {
    return this.ws.connect()
  }

  stop (): void {
    this.ws.close()
  }

  /** 一帧内可能包含多类推送：先信号与通知，再普通消息 */
  private frame (frame: Frame): void {
    if (!SERVICES.has(frame.service) || frame.method !== 1) return
    try {
      const payload = frame.encoding === '__lz4' ? lz4(frame.payload) : frame.payload
      for (const notice of extractAndroidNotices(payload)) this.route(notice)
      for (const reaction of extractReactions(payload)) this.emit('notice', reaction)
      for (const push of extractAndroidPushes(payload)) this.dispatch(push)
    } catch (error) {
      this.log.warn(`App 推送解析失败：${String(error)}`)
    }
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
    if (push.senderUid === this.uid() && !this.selfMessage) return
    const event = push.isThreadRoot ? undefined : noticeFromPush(push)
    if (event) {
      this.route(event)
      return
    }
    this.emit('message', toInboundMessage(push))
  }

  /** uid 在登录后才写入 jar，连接建立前不能缓存 */
  private uid (): string {
    return this.auth.jar.get('uid') ?? ''
  }

  /** 好友申请/入群申请走 request，其余通知走 notice */
  private route (event: NoticeEvent | RequestEvent): void {
    if (event.type === 'friend.request' || event.type === 'group.join-request') this.emit('request', event)
    else this.emit('notice', event)
  }
}
