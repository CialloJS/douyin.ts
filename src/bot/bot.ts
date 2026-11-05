/** SDK 门面：统一 `bot.域.动作`。收消息走 Android Frontier WS，发消息统一 HTTP cookie 通道 */
import { err } from '../error.js'
import { Http } from '../session/http.js'
import { createLog } from '../session/log.js'
import { createDevice } from '../session/device.js'
import { Emitter } from '../session/emitter.js'
import { mac } from '../session/sign/const.js'
import { self } from '../contact/self.js'
import { getFriendList } from '../contact/friend.js'
import { getStrangerList } from '../contact/stranger.js'
import { getUserProfiles } from '../contact/users.js'
import { getGroupMembers } from '../chat/group.js'
import { getVideoUrl } from '../media/play.js'
import { chatIdOf, toAddress } from './address.js'
import { createCtx, type Ctx } from './ctx.js'
import { Nicks } from './nick.js'
import { Receiver } from './receive.js'
import { Msg } from './msg.js'
import { Media } from './media.js'
import { Frd } from './frd.js'
import { Grp } from './grp.js'
import { Chat } from './chat.js'
import { User } from './user.js'
import { Sticker } from './sticker.js'
import { Social } from './social.js'
import { Watch } from './watch.js'
import { Notice } from './notice.js'
import { Setting } from './setting.js'
import type { BotEventMap, BotOpts, Device, InboundMessage, Log } from '../types.js'

export class Bot extends Emitter<BotEventMap> {
  readonly msg = new Msg(this)
  readonly media = new Media(this)
  readonly frd = new Frd(this)
  readonly grp = new Grp(this)
  readonly chat = new Chat(this)
  readonly user = new User(this)
  readonly sticker = new Sticker(this)
  readonly social = new Social(this)
  readonly watch = new Watch(this)
  readonly notice = new Notice(this)
  readonly setting = new Setting(this)

  private readonly opts: BotOpts
  private readonly log: Log
  private readonly nicks = new Nicks()
  private userId = ''
  private core?: Ctx
  private receiver?: Receiver

  constructor (opts: BotOpts) {
    super()
    this.opts = opts
    this.log = opts.log ?? createLog({ tag: 'bot' })
  }

  /** 自身数字 uid（start 后可用） */
  get id (): string {
    return this.userId
  }

  /** 当前设备身份（start 后可用）；持久化后下次构造用 opts.device 注入，避免重复注册 */
  get device (): Device | undefined {
    const http = this.core?.http
    if (!http || !http.hasDevice()) return undefined
    return { deviceId: http.deviceId, installId: http.installId, guid: http.guid }
  }

  async start (): Promise<void> {
    if (this.receiver) return
    const http = new Http({
      cookie: this.opts.cookie,
      userId: this.opts.userId,
      userAgent: this.opts.userAgent ?? mac.ua,
      timeout: this.opts.timeout,
      log: this.log,
    })
    let userId = this.opts.userId ?? ''
    if (!userId) {
      const info = await self(http)
      if (!info.uid) return err(info)
      userId = info.uid
      if (info.nickname) this.nicks.set(userId, info.nickname)
    }
    if (this.opts.device) http.setDevice(this.opts.device)
    else if (!http.hasDevice()) http.setDevice(await createDevice(this.log))

    const options = {
      http,
      userId,
      cookies: this.opts.cookie,
      deviceId: http.deviceId,
      selfMessage: this.opts.selfMessage,
      log: this.log,
    }
    this.core = createCtx(options)
    this.receiver = new Receiver(options)
    this.userId = userId
    this.wire(this.receiver)
    // 预热好友昵称缓存（与 WS 握手并行），常见私聊对象首条消息即命中
    void getFriendList(this.core.inbox).then(list => this.nicks.remember(list)).catch(() => undefined)
    await this.receiver.start()
  }

  stop (): void {
    this.receiver?.stop()
  }

  /** 域方法内部取用；未启动即抛出 */
  ctx (): Ctx {
    if (!this.core) return err({ started: false })
    return this.core
  }

  http (): Http {
    return this.ctx().http
  }

  rememberNicks (entries: readonly { uid: string; nickname?: string; alias?: string }[]): void {
    this.nicks.remember(entries)
  }

  /** 按 uid 查昵称：TTL 内命中直接返回；未命中拉一次好友列表整体回填（发送 @ 自动补昵称用） */
  async nickOf (uid: string): Promise<string | undefined> {
    const cached = this.nicks.get(uid)
    if (cached !== undefined) return cached
    this.nicks.remember(await getFriendList(this.ctx().inbox).catch(() => []))
    return this.nicks.get(uid)
  }

  /** 发送者昵称补拉：同 uid 并发去重；失败静默不影响下发 */
  private ensureNick (msg: InboundMessage): Promise<void> {
    if (msg.senderUid === this.userId || this.nicks.has(msg.senderUid)) return Promise.resolve()
    return this.nicks.once(msg.senderUid, () => this.fetchNick(msg))
  }

  private async fetchNick (msg: InboundMessage): Promise<void> {
    if (msg.conversationType === 2) {
      // 群：拉全群 uid+secUid（顺带缓存群昵称 alias），资料接口批量回填昵称
      const members = await getGroupMembers(this.ctx().inbox, toAddress(chatIdOf(msg)))
      this.nicks.remember(members)
      const profiles = await getUserProfiles(this.ctx().http, members.map(m => m.secUid ?? ''))
      for (const m of members) {
        const nickname = m.secUid ? profiles.get(m.secUid)?.nickname : undefined
        if (nickname) this.nicks.set(m.uid, nickname)
      }
      return
    }
    if (msg.senderSecUid) {
      // 私聊：推送自带发送者 secUid，单次资料查询即可
      const profiles = await getUserProfiles(this.ctx().http, [msg.senderSecUid])
      const nickname = profiles.get(msg.senderSecUid)?.nickname
      if (nickname) this.nicks.set(msg.senderUid, nickname)
      return
    }
    const [friends, strangers] = await Promise.all([
      getFriendList(this.ctx().inbox),
      getStrangerList(this.ctx().inbox),
    ])
    this.nicks.remember([...friends, ...strangers])
  }

  /** 把接收层推送接到 Bot 事件层：message 类补 chatId 与昵称，其余原样透传 */
  private wire (receiver: Receiver): void {
    receiver.on('message', msg => void this.forward('message', msg))
    receiver.on('message:edited', msg => void this.forward('message:edited', msg))
    receiver.on('notice', event => this.emit('notice', event))
    receiver.on('request', event => this.emit('request', event))
    receiver.on('voip', event => this.emit('voip', event))
    receiver.on('read', event => this.emit('read', event))
    receiver.on('status', event => this.emit('status', event))
    receiver.on('reconnecting', event => this.emit('reconnecting', event))
    receiver.on('close', event => this.emit('close', event))
  }

  /** 等昵称与视频地址补拉完成再下发，首条消息即带完整字段 */
  private async forward (event: 'message' | 'message:edited', msg: InboundMessage): Promise<void> {
    await Promise.all([this.ensureNick(msg), this.ensureVideoUrl(msg)])
    this.emit(event, { ...msg, chatId: chatIdOf(msg), senderNickname: this.nicks.get(msg.senderUid) })
  }

  /** 视频播放地址补拉：随事件直接下发，失败静默（调用方仍可 media.videoUrl 手动换） */
  private async ensureVideoUrl (msg: InboundMessage): Promise<void> {
    if (msg.type !== 'video' || !('url' in msg.video)) return
    try {
      msg.video.url = await getVideoUrl(this.ctx().http, msg.video.tkey)
    } catch {
      // 换取失败不阻塞下发
    }
  }
}
