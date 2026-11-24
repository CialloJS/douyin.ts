/** bot.app：设备注册、App 登录与 IM 加密通道的两级门面 */
import { createLog } from '../session/log.js'
import { Recv } from './recv.js'
import type { ImEventMap, Log } from '../types.js'
import { DEV } from './conf.js'
import { fill } from './ids.js'
import { Auth } from './auth.js'
import { Login } from './login.js'
import { device as reg, activate } from './device.js'
import { Im, type Call, type ImRes } from './im.js'
import { eeEntry, type EeEntry } from './ee.js'
import { read, type Challenge } from './captcha.js'
import { serve, type Slide, type SlideOpts } from './slide.js'
import { Conv, type ConvId, type ConvPage, type HistoryOpts, type ReadOpts, type UserMsgOpts, type SendOpts, type CreateOpts, type AuditOpts, type StrangerOpts, type RecentStrangerOpts, type MemberOpts, type MarkOpts, type CmdOpts, type RangeOpts, type InitOpts, type ThreadOpts, type TimeOpts, type CmdRangeOpts, type SpecifiedOpts, type MsgMarkOpts, type ExtOpts, type DelOpts, type ThreadSubOpts, type ReactOpts } from './conv.js'
import { Account } from './account.js'
import { Notice } from './notice.js'
import { Friend, type ApplyOpts } from './friend.js'
import { Resource } from './resource.js'
import { Social } from './social.js'
import { Group } from './group.js'
import { Config } from './config.js'
import { Growth } from './growth.js'
import { ChatAi } from './chatai.js'
import { Comm } from './comm.js'
import { Media } from './media.js'
import { Send } from './send.js'
import type { AppOpts, Dev, Ids, LoginData, VerifyWay, CaptchaCredential } from './types.js'

/** 扫码轮询间隔：与真机一致 2s，过快会被服务端按 2156/7「系统繁忙」限流 */
const QR_POLL = 2000
/** 上行短信轮询：等用户发短信 */
const UP_POLL = 2000
const UP_TRIES = 30
/** 一次决策失败后重发登录取新决策的轮数；5014 属环境判定，不在本循环内硬试 */
const SLIDE_TRIES = 3

export interface MfaAsk {
  way: string
  kind: 'sms' | 'password' | 'up-sms' | 'qr'
  /** 掩码手机号 */
  mobile?: string
  /** 上行短信内容让用户发到该号码 */
  sms?: { content: string; mobile?: string }
  qr?: { url: string; base64?: string }
}

export interface VerifyOpts {
  /** 1105 滑块：把挑战交给调用方，回填 ticket 后重试 */
  onCaptcha?: (c: Challenge) => CaptchaCredential | Promise<CaptchaCredential>
  /** 1105 滑块：起本地验证页让手机拖动，通过后自动回填票据重发；传对象可改端口/超时 */
  slide?: boolean | SlideOpts
  /** 已输入的密码：2046 要求密码验证时直接复用，不再重复询问 */
  password?: string
  /** 二次验证：返回短信验证码 / 密码；返回空串表示重发短信 */
  onMfa?: (m: MfaAsk) => string | Promise<string>
  /** 二次验证方式选择：返回 verify_way 或下标；未提供时按内置优先级自动选 */
  onWay?: (ways: VerifyWay[]) => string | number | Promise<string | number>
  /** MFA 扫码图 */
  onQr?: (qr: { url: string; base64?: string }) => void | Promise<void>
  /** 扫码状态变化：status + error_code */
  onStatus?: (s: string, code: number) => void | Promise<void>
}

export interface SmsOpts extends VerifyOpts {
  mobile: string
  /** 直接给验证码；或用 onCode 在发码成功后再询问 */
  code?: string
  onCode?: () => string | Promise<string>
}

export interface PwdOpts extends VerifyOpts {
  mobile: string
  password: string
}

export interface CodeRes {
  sent: boolean
  data: LoginData
  /** 1105 滑块挑战 */
  captcha?: Challenge
}

export interface LoginRes {
  ok: boolean
  userId: string
  cookie: string
  ids: Ids
  data: LoginData
  /** 未提供 onMfa 时返回服务端可用的二次验证方式 */
  ways?: VerifyWay[]
}

export interface DeviceOpts {
  /** true 时丢弃已有 device_id 重新注册 */
  force?: boolean
  host?: string
}

export class App {
  readonly dev: Dev
  readonly ids: Ids
  readonly auth: Auth
  readonly log: Log
  private flow?: Login
  private agent?: Im
  private convBot?: Conv
  private accountBot?: Account
  private noticeBot?: Notice
  private friendBot?: Friend
  private resourceBot?: Resource
  private socialBot?: Social
  private groupBot?: Group
  private configBot?: Config
  private growthBot?: Growth
  private chatAiBot?: ChatAi
  private commBot?: Comm
  private mediaBot?: Media
  private sendBot?: Send
  private recvBot?: Recv

  constructor (opts: AppOpts = {}) {
    this.dev = { ...DEV, ...opts.dev }
    this.ids = fill(opts.ids)
    // 注册下发的 odin_tt 属于设备身份的一部分，必须和登录 cookie 一起进会话
    this.auth = new Auth([this.ids.cookie, opts.cookie].filter(Boolean).join('; '))
    this.log = opts.log ?? createLog({ tag: 'app' })
  }

  /** 注册并激活新设备（结果由调用方持久化后回传） */
  async device (opts: DeviceOpts = {}): Promise<Ids> {
    // 换设备会让绑定该 device_id 的登录态全部失效；只有显式 force 才允许换
    if (!opts.force && this.ids.device_id) {
      // 复用身份也要重新激活：激活按启动会话生效，未激活的设备会在扫码确认阶段被判 7
      if (!(await activate(this.ids, { host: opts.host }))) this.log.warn('设备激活失败，继续使用原设备')
      this.log.info('设备已激活')
      return this.ids
    }
    // force 视为重新装机：旧 cookie 与新设备必然串号，必须一起丢弃
    if (opts.force) this.auth.reset()
    Object.assign(this.ids, fill({ first_install: this.ids.first_install }))
    const next = await reg(this.ids, { host: opts.host })
    Object.assign(this.ids, next)
    this.auth.jar.merge(next.cookie ?? '')
    this.log.info(`设备注册成功 device_id=${next.device_id}`)
    return this.ids
  }

  /** 仅发送验证码；1105 时返回 captcha 交给调用方处理 */
  async code (mobile: string, cred: CaptchaCredential = {}): Promise<CodeRes> {
    const f = this.begin(mobile)
    const data = await f.sendCode(cred)
    return { sent: Number(data.error_code) === 0, data, captcha: read(f.last) }
  }

  /** 为当前 1105 挑战起本地验证页；手机扫码拖动通过后 wait() 完成，再回填票据重发 */
  async slide (opts: SlideOpts = {}): Promise<Slide> {
    const ch = read(this.login.last)
    if (!ch) throw new Error('当前没有滑块挑战，请先发送验证码')
    return serve({ challenge: ch, dev: this.dev, ids: this.ids, auth: this.auth, ...opts })
  }

  /** 验证码登录（含 1105 重试与 2046 二次验证） */
  async sms (opts: SmsOpts): Promise<LoginRes> {
    const f = this.begin(opts.mobile)
    const sent = await this.retry(c => f.sendCode(c), opts, 'tt_send_sms_login')
    if (Number(sent.error_code) !== 0) return this.res(sent)
    // 发码成功后再询问：日志中先出现 send_code 请求，而不是等输入完才发
    const code = opts.code ?? (opts.onCode ? await opts.onCode() : '')
    if (!code) return this.res(sent)
    return this.finish(await f.smsLogin(code), opts)
  }

  /** 密码登录（含 1105 重试与 2046 二次验证） */
  async pwd (opts: PwdOpts): Promise<LoginRes> {
    const f = this.begin(opts.mobile)
    const data = await this.retry(c => f.pwdLogin(opts.password, undefined, c), opts, 'tt_mobile_pwd_login')
    return this.finish(data, opts)
  }

  /** 扫码登录（含二次验证：验证完成后重放 check_qrconnect） */
  async qr (opts: VerifyOpts = {}): Promise<LoginRes> {
    let data: LoginData = {}
    let auth = new Auth()
    // 二维码是独立会话：过期就换一张，避免复用上一张码的 cookie/token 被服务端拒绝
    for (let round = 0; round < 3; round++) {
      // 用独立 jar，扫码失败时主会话里已登录的 ck 不受影响
      auth = new Auth()
      const f = this.begin('', auth)
      const code = await f.qrGetCode()
      const index = String(code.qrcode_index_url ?? '')
      const raw = String(code.qrcode ?? '')
      if (Number(code.error_code) !== 0 || (!index && !raw)) return this.res(code)
      // qrcode_index_url 才是二维码内容；qrcode 多为服务端渲染的 PNG，二选一
      const url = index || (raw.startsWith('http') ? raw : '')
      const base64 = raw && !raw.startsWith('http') ? raw : undefined
      await opts.onQr?.({ url, base64 })

      const token = String(code.token ?? '')
      if (!token) return this.res(code)
      data = code
      let last = ''
      let refresh = false
      const expire = Number(code.expire_time ?? 0) * 1000
      for (let i = 0; i < 120; i++) {
        await sleep(QR_POLL)
        if (expire && Date.now() > expire - 5_000) {
          refresh = true
          break
        }
        data = await f.qrCheck(token)
        const st = String(data.status ?? '')
        const ec = Number(data.error_code ?? 0)
        // scanned 会持续返回；只在状态或错误码变化时回调
        if (`${st}|${ec}` !== last) {
          last = `${st}|${ec}`
          await opts.onStatus?.(st, ec)
        }
        if (ec === 2046) break
        // 7/2156 是服务端对整张码的拒绝，同一 token 继续轮询只会一直是 7
        if (ec > 0) return this.res(data)
        if (st === 'confirmed') break
        if (st === 'expired' || st === 'canceled') return this.res(data)
      }
      if (!refresh) break
    }
    const res = await this.finish(data, opts)
    // 扫码成功才把独立会话合并进主会话；失败/取消保留原有 ck
    if (auth.jar.get('sessionid')) {
      this.auth.jar.merge(auth.cookie())
      return { ...res, ok: true, cookie: this.auth.cookie() }
    }
    return res
  }

  /** 手动提交二次验证（未给 onMfa 回调时使用）：kind=sms/password/upsms */
  async mfa (kind: 'sms' | 'password' | 'upsms' | 'qr', input = ''): Promise<LoginRes> {
    const f = this.login
    const data =
      kind === 'password'
        ? await f.accountVerify(input)
        : kind === 'sms'
          ? await f.validateCode(input)
          : kind === 'upsms'
            ? await f.upSmsVerify()
            : await f.mfaQrCheck(input)
    // 验证接口只换到 ticket；必须重放原 2046 请求，服务端才会建会话
    if (Number(data.error_code ?? 0) !== 0 || !f.waiting) return this.finish(data, {})
    return this.finish(await f.replayLogin(), {})
  }

  /** 账号信息（需已登录 Cookie） */
  async info (): Promise<LoginData> {
    return this.login.accountInfo()
  }

  /** 当前登录态 */
  token (): { cookie: string; userId?: string } {
    return { cookie: this.auth.cookie(), userId: this.auth.jar.get('uid') ?? undefined }
  }

  /** 订阅 App 推送事件：事件名与 bot.on 一致，来源是 App Frontier 长连接 */
  on<K extends keyof ImEventMap> (event: K, fn: (...args: ImEventMap[K]) => void): void {
    this.recv.on(event, fn)
  }

  /** 建立 App Frontier 长连接（需已登录，握手带 X-Tt-Token） */
  start (): Promise<void> {
    return this.recv.start()
  }

  stop (): void {
    this.recvBot?.stop()
  }

  get connected (): boolean {
    return this.recvBot?.connected ?? false
  }

  /** 关闭/开启「保存登录信息」 */
  async record (status: 1 | 2): Promise<LoginData> {
    return this.login.record(status)
  }

  /** keyhub 握手结果（IM 加密密钥） */
  async key (): Promise<{ ticket: string; key: string; expiresAt: number }> {
    const s = await this.agentOf().key()
    return { ticket: s.ticket, key: s.keyIM.toString('base64'), expiresAt: s.expiresAt }
  }

  /** 调用 IM 接口（默认按端点表加密 pb） */
  async im (call: Call = {}): Promise<ImRes> {
    return this.agentOf().call(call)
  }

  /** 导出 ee.info 96B key 包，供外部进程复用 IM 会话 */
  async ee (id?: string): Promise<EeEntry> {
    const agent = this.agentOf()
    return eeEntry(await agent.key(), id ?? `${await agent.uid()}+IM`)
  }

  /** 会话列表（pb cmd=2006） */
  convList (opts: ConvPage = {}): Promise<Record<string, unknown>> {
    return this.conv.list(opts)
  }

  /** 批量会话详情（pb cmd=610） */
  convInfos (list: ConvId[]): Promise<Record<string, unknown>> {
    return this.conv.infos(list)
  }

  /** 单个会话详情（pb cmd=608） */
  convInfo (id: ConvId): Promise<Record<string, unknown>> {
    return this.conv.info(id)
  }

  /** 历史消息（pb cmd=301） */
  history (opts: HistoryOpts): Promise<Record<string, unknown>> {
    return this.conv.history(opts)
  }

  /** 标记已读（pb cmd=2002） */
  read (opts: ReadOpts): Promise<Record<string, unknown>> {
    return this.conv.read(opts)
  }

  /** 成员已读游标（pb cmd=2000） */
  readIndex (id: ConvId): Promise<Record<string, unknown>> {
    return this.conv.readIndex(id)
  }

  /** 最小同步游标（pb cmd=2001） */
  minIndex (id: ConvId): Promise<Record<string, unknown>> {
    return this.conv.minIndex(id)
  }

  /** 消息索引统计（pb cmd=12048） */
  userMessage (opts: UserMsgOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.userMessage(opts)
  }

  /** 发送消息（pb cmd=100）；媒体输入源自动上传，forward 走 App 域注册 */
  send (opts: SendOpts): Promise<Record<string, unknown>> {
    return this.sender.send(opts)
  }

  /** 表情回应（pb cmd=705）；emoji 传键值如 [爱心]，false 取消 */
  react (opts: ReactOpts): Promise<Record<string, unknown>> {
    return this.conv.react(opts)
  }

  /** 创建会话（pb cmd=609） */
  createConv (opts: CreateOpts): Promise<Record<string, unknown>> {
    return this.conv.create(opts)
  }

  /** 陌生人会话列表（pb cmd=1001） */
  strangerList (opts: StrangerOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.strangerList(opts)
  }

  /** 会话审核列表（pb cmd=2027） */
  auditList (opts: AuditOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.auditList(opts)
  }

  /** 批量查成员已读游标（pb cmd=2038） */
  participantsReadIndex (id: ConvId): Promise<Record<string, unknown>> {
    return this.conv.participantsReadIndex(id)
  }

  /** 最近陌生人消息（pb cmd=12047） */
  recentStranger (opts: RecentStrangerOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.recentStranger(opts)
  }

  /** 会话参与者分页（pb cmd=605） */
  participants (opts: MemberOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.participants(opts)
  }

  /** 会话成员列表（pb cmd=12060） */
  members (opts: MemberOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.members(opts)
  }

  /** 批量取多个会话成员（pb cmd=12061） */
  membersBatch (list: MemberOpts[]): Promise<Record<string, unknown>> {
    return this.conv.membersBatch(list)
  }

  /** 按 uid 精确取成员（pb cmd=654） */
  membersByUid (id: ConvId, users: Array<string | number>): Promise<Record<string, unknown>> {
    return this.conv.membersByUid(id, users)
  }

  /** 按标记位增量拉消息（pb cmd=2037） */
  marks (opts: MarkOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.marks(opts)
  }

  /** 最近控制类消息会话（pb cmd=12062） */
  cmds (opts: CmdOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.cmds(opts)
  }

  /** 会话内控制类消息（pb cmd=2040） */
  cmdMessages (opts: CmdOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.cmdMessages(opts)
  }

  /** 会话内 v2 索引区间消息（pb cmd=2041） */
  msgRange (opts: RangeOpts): Promise<Record<string, unknown>> {
    return this.conv.range(opts)
  }

  /** 冷启动首屏消息（pb cmd=2043） */
  msgInit (opts: InitOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.init(opts)
  }

  /** 盖楼消息冷启动（pb cmd=2204） */
  threadInit (opts: ThreadOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.thread(opts)
  }

  /** 按服务端消息 id 取单条（pb cmd=211） */
  msg (id: ConvId, messageId: string | number, onlyStatus = false): Promise<Record<string, unknown>> {
    return this.conv.msg(id, messageId, onlyStatus)
  }

  /** 按服务端消息 id 批量取（pb cmd=212） */
  msgs (id: ConvId, messageIds: Array<string | number>): Promise<Record<string, unknown>> {
    return this.conv.msgs(id, messageIds)
  }

  /** 按时间翻页取消息（pb cmd=310） */
  byTime (opts: TimeOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.byTime(opts)
  }

  /** 消息标记/取消标记（pb cmd=2036） */
  mark (opts: MsgMarkOpts): Promise<Record<string, unknown>> {
    return this.conv.mark(opts)
  }

  /** 修改消息扩展与内容（pb cmd=2021） */
  modifyExt (opts: ExtOpts): Promise<Record<string, unknown>> {
    return this.conv.modifyExt(opts)
  }

  /** 控制类消息区间（pb cmd=12040） */
  cmdRange (opts: CmdRangeOpts = {}): Promise<Record<string, unknown>> {
    return this.conv.cmdRange(opts)
  }

  /** 指定类型消息列表（pb cmd=12050） */
  specified (opts: SpecifiedOpts): Promise<Record<string, unknown>> {
    return this.conv.specified(opts)
  }

  /** 收藏会话列表（pb cmd=611） */
  favorite (opts: { cursor?: string | number; limit?: number } = {}): Promise<Record<string, unknown>> {
    return this.conv.favorite(opts)
  }

  /** 置顶会话列表（pb cmd=612） */
  top (opts: { cursor?: string | number; limit?: number; type?: number } = {}): Promise<Record<string, unknown>> {
    return this.conv.top(opts)
  }

  /** 批量标记已读（pb cmd=613） */
  batchRead (list: ReadOpts[]): Promise<Record<string, unknown>> {
    return this.conv.batchRead(list)
  }

  /** 批量删除会话（pb cmd=619） */
  batchDelete (list: DelOpts[]): Promise<Record<string, unknown>> {
    return this.conv.batchDelete(list)
  }

  /** 清空会话消息（pb cmd=620） */
  clearMsg (opts: DelOpts): Promise<Record<string, unknown>> {
    return this.conv.clearMsg(opts)
  }

  /** 最近陌生人会话（pb cmd=12063） */
  recentStrangerConv (opts: { max?: string | number; min?: string | number; reverse?: boolean; source?: string } = {}): Promise<Record<string, unknown>> {
    return this.conv.recentStrangerConv(opts)
  }

  /** 盖楼订阅状态（pb cmd=2205） */
  threadSub (opts: ThreadSubOpts): Promise<Record<string, unknown>> {
    return this.conv.threadSub(opts)
  }

  /** 本人主页 */
  self (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.self(query)
  }

  /** 他人主页（sec_user_id） */
  other (secUserId: string, query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.other(secUserId, query)
  }

  /** 主页场景配置 */
  scene (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.scene(query)
  }

  /** 个人设置 */
  userSettings (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.userSettings(query)
  }

  /** 全局设置 */
  settings (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.settings(query)
  }

  /** 社交关系设置 */
  socialSettings (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.socialSettings(query)
  }

  /** 社交计数（zstd-form） */
  socialCount (body: string): Promise<Record<string, unknown>> {
    return this.account.socialCount(body)
  }

  /** 合规设置 */
  compliance (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.compliance(query)
  }

  /** 封禁信息 */
  ban (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.ban(query)
  }

  /** 紧急禁用状态 */
  forbid (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.forbid(query)
  }

  /** DX 状态 */
  dx (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.dx(query)
  }

  /** 资料同步提示 */
  syncTips (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.syncTips(query)
  }

  /** 隐私图片 */
  privacyImage (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.account.privacyImage(query)
  }

  /** 通知未读数 */
  noticeCount (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.notice.count(query)
  }

  /** 通知列表 */
  noticeList (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.notice.list(query)
  }

  /** 好友推荐 */
  recommend (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.friend.recommend(query)
  }

  /** 推荐候选 topK */
  topk (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.friend.topk(query)
  }

  /** 新推荐用户数量 */
  recommendCount (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.friend.recommendCount(query)
  }

  /** 收到的好友申请（pb cmd=2048） */
  applies (opts: ApplyOpts = {}): Promise<Record<string, unknown>> {
    return this.friend.applies(opts)
  }

  /** 熟人视频访客列表 */
  visitors (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.social.visitors(query)
  }

  /** 熟人视频统计上报 */
  videoStats (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.social.videoStats(body)
  }

  /** VoIP 冷启动拉取 */
  voipColdPull (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.social.voipColdPull(query)
  }

  /** 收藏的用户列表 */
  collectUsers (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.social.collectUsers(query)
  }

  /** 审批好友申请（pb cmd=2049） */
  replyFriend (uids: Array<string | number>, attitude: 1 | 2): Promise<Record<string, unknown>> {
    return this.friend.reply(uids, attitude)
  }

  /** 资源位聚合 */
  resources (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.resource.resources(query)
  }

  /** 表情资源 */
  emoji (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.resource.emoji(query)
  }

  /** 表情搜索 */
  emoticon (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.resource.emoticon(query)
  }

  /** 打招呼贴纸 */
  helloSticker (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.resource.helloSticker(query)
  }

  /** 上传通道配置 */
  uploadConfig (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.resource.uploadConfig(query)
  }

  /** 收藏文件 */
  collectFile (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.resource.collectFile(query)
  }

  /** 好友相册列表 */
  album (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.resource.album(query)
  }

  /** 批量加入好友相册 */
  albumAdd (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.resource.albumAdd(body)
  }

  /** 关注关系推荐 */
  spotlight (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.social.spotlight(query)
  }

  /** 熟人设置 */
  familiar (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.social.familiar(query)
  }

  /** 用户推荐 */
  userRecommend (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.social.recommend(body)
  }

  /** 本地通讯录用户 */
  localUsers (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.social.localUsers(query)
  }

  /** 用户中心聚合 */
  center (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.social.center(body)
  }

  /** 用户中心计划 */
  centerPlan (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.social.centerPlan(body)
  }

  /** 用户中心同步 */
  centerSync (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.social.centerSync(body)
  }

  /** 用户中心消息同步 */
  centerMsgs (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.social.centerMsgs(body)
  }

  /** 我加入的群列表 */
  groups (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.groups(query)
  }

  /** 群指标 */
  indicators (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.indicators(body)
  }

  /** 区间群聊链条 */
  chains (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.chains(body)
  }

  /** 按群 id 取链条 */
  chain (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.chain(body)
  }

  /** 群打卡信息 */
  checkin (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.checkin(body)
  }

  /** 群打卡权限校验 */
  checkinAuth (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.checkinAuth(body)
  }

  /** 成员设置更新 */
  memberSettings (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.memberSettings(body)
  }

  /** 群操作扫描 */
  groupScan (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.scan(query)
  }

  /** 群标签扫描 */
  groupTags (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.tags(query)
  }

  /** 群活跃信息 */
  active (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.active(body)
  }

  /** 群活跃信息扫描 */
  activeScan (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.activeScan(query)
  }

  /** 群号 */
  groupNumber (shortId: string | number): Promise<Record<string, unknown>> {
    return this.group.number(shortId)
  }

  /** 群资料更新 */
  updateGroup (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.updateGroup(body)
  }

  /** 群可见范围 */
  visible (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.visible(body)
  }

  /** 群合照样式 */
  mixPhoto (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.mixPhoto(query)
  }

  /** 群资料校验 */
  validate (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.validate(query)
  }

  /** 群升级信息 */
  upgrade (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.upgrade(query)
  }

  /** 群升级信息列表 */
  upgrades (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.upgrades(query)
  }

  /** 会话悬浮条是否展示 */
  floatingCheck (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.conv.floatingCheck(query)
  }

  /** 会话悬浮条配置 */
  floatingConfigs (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.conv.floatingConfigs(query)
  }

  /** 默认聊天背景图 */
  backgrounds (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.conv.backgrounds(query)
  }

  /** 会话场景信息 */
  convScene (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.conv.scene(query)
  }

  /** 会话附加信息 */
  convOther (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.conv.other(body)
  }

  /** 会话可打开应用列表 */
  openApps (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.conv.openApps(body)
  }

  /** 推荐折叠群 */
  foldGroups (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.foldGroups(query)
  }

  /** 群任务列表 */
  groupTasks (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.tasks(query)
  }

  /** 群任务更新 */
  groupTaskUpdate (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.taskUpdate(body)
  }

  /** 群操作批量校验 */
  groupMultiCheck (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.multiCheck(body)
  }

  /** 入群门槛设置 */
  entryLimit (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.entryLimit(query)
  }

  /** 群聊词库设置 */
  groupWords (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.words(query)
  }

  /** 群广场热点 */
  groupHotspot (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.hotspot(body)
  }

  /** 群广场推荐 */
  groupRecommend (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.recommend(body)
  }

  /** 群广场信息 */
  groupSquare (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.square(body)
  }

  /** 群广场搜索 */
  groupSearch (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.group.searchGroups(body)
  }

  /** 群操作前置校验 */
  groupActionCheck (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.actionCheck(query)
  }

  /** 按群 id 批量取群 */
  groupOthers (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.others(query)
  }

  /** 建群面板信息 */
  groupPanel (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.panel(query)
  }

  /** 可邀请的粉丝列表 */
  groupFansList (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.fansList(query)
  }

  /** 粉丝群卡片状态 */
  groupFansCard (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.group.fansCard(query)
  }

  /** 客户端 IM 配置 */
  imConfig (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.config.base(query)
  }

  /** 服务端全局配置 */
  globalConfig (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.config.global(query)
  }

  /** 策略配置 */
  strategyConfig (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.config.strategy(query)
  }

  /** 重启降级配置 */
  rebootConfig (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.config.reboot(query)
  }

  /** 用户活跃配置 */
  activeConfig (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.config.active(query)
  }

  /** 用户活跃心跳更新 */
  activeUpdate (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.config.activeUpdate(query)
  }

  /** 上报用户活跃状态 */
  activeStatus (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.config.activeStatus(body)
  }

  /** 进入会话上报 */
  enterChat (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.config.enterChat(body)
  }

  /** 进入消息 Tab 上报 */
  msgTabEnter (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.config.msgTabEnter(body)
  }

  /** 连续聊天关系成就 */
  consecutive (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.growth.consecutive(query)
  }

  /** 成长分享列表 */
  growthShare (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.growth.shareList(body)
  }

  /** 连续聊天开关 */
  consecutiveSwitch (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.growth.switch(body)
  }

  /** 连续聊天上报 */
  consecutiveReport (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.growth.report(body)
  }

  /** 动态策略 */
  growthDynamic (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.growth.dynamic(body)
  }

  /** 语音识别模型配置 */
  audioModel (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.growth.audioModel(query)
  }

  /** 火焰成就 */
  flame (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.growth.flame(query)
  }

  /** Gaga 聚合信息 */
  gaga (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.chatAi.gaga(body)
  }

  /** 宠物聚合信息 */
  pet (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.chatAi.pet(body)
  }

  /** 宠物精灵邀请卡 */
  petCard (query?: Record<string, string | number>): Promise<Record<string, unknown>> {
    return this.chatAi.petCard(query)
  }

  /** 子弹事件请求并更新 */
  bullet (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.chatAi.bullet(body)
  }

  /** 子弹事件数据提交 */
  bulletSubmit (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.chatAi.bulletSubmit(body)
  }

  /** 实验命中查询 */
  expHit (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.comm.expHit(body)
  }

  /** 合并消息卡准备 */
  mergePrepare (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.comm.mergePrepare(body)
  }

  /** 通信杂项上报 */
  commMisc (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.comm.misc(body)
  }

  /** 分享上报 */
  shareReport (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.comm.shareReport(body)
  }

  private get conv (): Conv {
    return this.convBot ??= new Conv(this.agentOf(), this.dev, this.ids)
  }

  private get account (): Account {
    return this.accountBot ??= new Account(this.agentOf())
  }

  private get notice (): Notice {
    return this.noticeBot ??= new Notice(this.agentOf())
  }

  private get friend (): Friend {
    return this.friendBot ??= new Friend(this.agentOf(), this.dev, this.ids)
  }

  private get resource (): Resource {
    return this.resourceBot ??= new Resource(this.agentOf())
  }

  private get social (): Social {
    return this.socialBot ??= new Social(this.agentOf())
  }

  private get group (): Group {
    return this.groupBot ??= new Group(this.agentOf())
  }

  private get config (): Config {
    return this.configBot ??= new Config(this.agentOf())
  }

  private get growth (): Growth {
    return this.growthBot ??= new Growth(this.agentOf())
  }

  private get chatAi (): ChatAi {
    return this.chatAiBot ??= new ChatAi(this.agentOf())
  }

  private get comm (): Comm {
    return this.commBot ??= new Comm(this.agentOf())
  }

  private get media (): Media {
    return this.mediaBot ??= new Media(this.agentOf(), this.auth)
  }

  private get sender (): Send {
    return this.sendBot ??= new Send(this.conv, this.media, this.comm)
  }

  private get recv (): Recv {
    if (!this.recvBot) this.recvBot = new Recv({ dev: this.dev, ids: this.ids, auth: this.auth, log: this.log })
    return this.recvBot
  }

  private get login (): Login {
    if (!this.flow) this.flow = new Login({ auth: this.auth, dev: this.dev, ids: this.ids })
    return this.flow
  }

  private begin (mobile: string, auth: Auth = this.auth): Login {
    this.flow = new Login({ auth, dev: this.dev, ids: this.ids, mobile })
    this.agent = undefined
    return this.flow
  }

  private agentOf (): Im {
    if (!this.agent) this.agent = new Im({ dev: this.dev, ids: this.ids, auth: this.auth })
    return this.agent
  }

  /**
   * 1105 滑块：回调换 ticket 后重试；没给回调但开了 slide 就起本地验证页并自动续跑。
   * 真机 HAR 实测同一 detail 在 500 后可重新 get 新题再验（native SDK 行为），
   * 因此页面内换题由 slide 自己完成；本层只在决策整体失效时重发登录取新决策。
   */
  private async retry (call: (cred: CaptchaCredential) => Promise<LoginData>, opts: VerifyOpts, event: string): Promise<LoginData> {
    let data = await call({})
    if (Number(data.error_code) !== 1105) return data
    const first = read(this.login.last)
    if (!first) return data
    // 决策是 verify_center 下发的网页形态，但真机 native SDK 也用它起验证；改写时统一成 shark_admin
    this.log.info(`滑块决策 from=${String(first.decision['from'] ?? '')} 字段=${Object.keys(first.decision).length} subtype=${first.subtype}`)
    if (opts.onCaptcha) return call(await opts.onCaptcha(first))
    if (!opts.slide) return data
    for (let round = 0; round < SLIDE_TRIES; round++) {
      const ch = read(this.login.last)
      if (!ch) return data
      let page: Slide
      try {
        page = await serve({
          challenge: ch,
          dev: this.dev,
          ids: this.ids,
          auth: this.auth,
          event,
          ...(typeof opts.slide === 'object' ? opts.slide : {}),
        })
      } catch (e) {
        // 端口被占/无网卡等起页失败时保留 1105 结果，交给调用方处理
        this.log.warn(`本地验证页启动失败：${String(e)}`)
        return data
      }
      if (await page.wait()) return call({ verifyTicket: ch.verifyTicket })
      const why = page.result()
      if (why === 'timeout' || why === 'closed') return data
      if (why === 'cool') {
        // 5014 是设备/网络的「环境判定」，与答案对错、冷却时长都无关：换决策重试只会继续 5014
        this.log.warn('verify 5014（环境判定），需换网络后重试')
        return data
      }
      data = await call({})
      if (Number(data.error_code) !== 1105) return data
    }
    return data
  }

  /** 2046 二次验证：按优先级尝试，全部完成后重放原请求 */
  private async finish (first: LoginData, opts: VerifyOpts): Promise<LoginRes> {
    let data = first
    for (let round = 0; round < 3 && Number(data.error_code) === 2046; round++) {
      if (!opts.onMfa && !opts.onQr && !opts.password) return this.res(data)
      const next = await this.verifyOnce(data, opts)
      if (!next) return this.res(data)
      data = await this.login.replayLogin()
    }
    if (Number(data.error_code ?? 0) !== 0) return this.res(data)
    const info = await this.after(data)
    return { ...this.res(info), ok: Boolean(this.auth.sessionid) }
  }

  /** 处理一轮验证；返回 false 表示没有可用方式/用户取消 */
  private async verifyOnce (data: LoginData, opts: VerifyOpts): Promise<boolean> {
    const ways = (data.verify_ways ?? []) as VerifyWay[]
    const way = await this.wayOf(ways, opts)
    if (!way) return false
    const name = String(way.verify_way ?? '')
    const act = String(way.act_type ?? '22')
    if (name.includes('up_sms')) {
      await opts.onMfa?.({ way: name, kind: 'up-sms', sms: { content: String(way.sms_content ?? ''), mobile: way.channel_mobile } })
      for (let i = 0; i < UP_TRIES; i++) {
        const d = await this.login.upSmsVerify()
        if (d.registered === true || Number(d.error_code) === 0) return true
        await sleep(UP_POLL)
      }
      return false
    }
    if (name.includes('qr_code')) {
      if (!opts.onQr) return false
      const q = await this.login.mfaQrGetCode()
      const token = String(q.token ?? '')
      if (!token) return false
      const index = String(q.qrcode_index_url ?? '')
      const raw = String(q.qrcode ?? '')
      const url = index || (raw.startsWith('http') ? raw : '')
      const base64 = raw && !raw.startsWith('http') ? raw : undefined
      await opts.onQr({ url, base64 })
      let last = ''
      for (let i = 0; i < 60; i++) {
        await sleep(QR_POLL)
        const d = await this.login.mfaQrCheck(token)
        const st = String(d.status ?? '')
        const ec = Number(d.error_code ?? 0)
        if (`${st}|${ec}` !== last) {
          last = `${st}|${ec}`
          await opts.onStatus?.(st, ec)
        }
        if (st === 'confirmed' || st === 'scanned') return true
        if (st === 'expired' || st === 'canceled') return false
      }
      return false
    }
    if (name.includes('pwd')) {
      // 密码登录时用户已输入过密码，复用它可以避免二次询问同一个密码
      const pwd = opts.password ?? (opts.onMfa ? await opts.onMfa({ way: name, kind: 'password' }) : undefined)
      if (!pwd) return false
      await this.login.accountVerify(pwd)
      return true
    }
    // 人脸/钱包/邮箱类只能在 App 或钱包容器内完成，按短信接口硬发只会得到环境异常
    if (name && !name.includes('sms')) {
      this.log.warn(`该二次验证方式需在抖音 App 内完成：${name}`)
      return false
    }
    // mobile_sms_verify / assist_ 安全手机：空输入视为重发，最多三轮
    const mobile = String(way.channel_mobile ?? way.mobile ?? '').replace(/^\+?86/, '').replace(/\D/g, '')
    for (let tries = 0; tries < 3; tries++) {
      await this.login.mfaSendCode(act, mobile)
      const code = opts.onMfa ? await opts.onMfa({ way: name, kind: 'sms', mobile: String(way.mobile ?? mobile) }) : undefined
      if (!code) {
        this.log.info('未输入验证码，重新发送')
        continue
      }
      await this.login.validateCode(code, act)
      return true
    }
    return false
  }

  /** 选验证方式：交给调用方交互选择，缺省按内置优先级兜底 */
  private async wayOf (ways: VerifyWay[], opts: VerifyOpts): Promise<VerifyWay | undefined> {
    if (!ways.length) return undefined
    if (!opts.onWay) return pick(ways)
    const chosen = await opts.onWay(ways)
    if (typeof chosen === 'number') return ways[chosen]
    return ways.find(w => String(w.verify_way ?? '') === chosen) ?? pick(ways)
  }

  /** 登录收尾：update_token → 保存登录信息 → 账号信息 */
  private async after (data: LoginData): Promise<LoginData> {
    const f = this.login
    try {
      await f.updateToken()
    } catch (e) {
      this.log.warn(`update_token 失败：${String(e)}`)
    }
    try {
      await f.record(2)
    } catch (e) {
      this.log.warn(`保存登录信息失败：${String(e)}`)
    }
    try {
      const info = await f.accountInfo()
      return { ...data, ...info }
    } catch (e) {
      this.log.warn(`account/info 失败：${String(e)}`)
      return data
    }
  }

  private res (data: LoginData): LoginRes {
    const uid = String(data.user_id_str ?? data.user_id ?? data.uid ?? this.auth.jar.get('uid') ?? '')
    const ways = (data.verify_ways ?? []) as VerifyWay[]
    return { ok: false, userId: uid, cookie: this.auth.cookie(), ids: this.ids, data, ways: ways.length ? ways : undefined }
  }
}

/** 优先级：安全手机 → 绑定手机短信 → 上行短信 → 密码 → 扫码 */
function pick (ways: VerifyWay[]): VerifyWay | undefined {
  for (const w of ways) if (String(w.verify_way ?? '').startsWith('assist_') && String(w.verify_way).includes('sms')) return w
  for (const w of ways) if (String(w.verify_way ?? '').includes('mobile_sms_verify')) return w
  for (const w of ways) if (String(w.verify_way ?? '').includes('up_sms')) return w
  for (const w of ways) if (String(w.verify_way ?? '').includes('pwd')) return w
  return ways[0]
}

function sleep (ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
