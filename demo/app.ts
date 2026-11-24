/** App 域演示：设备注册、短信/密码/扫码登录、二次验证与 IM 加密通道，全部走 bot.app.* */
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { createInterface } from 'node:readline/promises'
import { fileURLToPath } from 'node:url'
import { toFile, toString as qrText } from 'qrcode'
import { Bot, createLog } from 'douyin.ts'
import type { AppWay, CaptchaCredential, Challenge, Ids, ImName, LoginRes, MfaAsk } from 'douyin.ts'

// 运行前先 pnpm build：demo 走包名自引用，加载 dist 产物
// 所有请求默认打印原始报文，APP_DEBUG=0 可关闭
if (!process.env.APP_DEBUG) process.env.APP_DEBUG = '1'
const log = createLog({ tag: 'app' })

process.on('unhandledRejection', reason => {
  log.error(`未处理拒绝: ${reason instanceof Error ? reason.stack ?? reason.message : String(reason)}`)
})
process.on('uncaughtException', error => {
  log.error(`未捕获异常: ${error.stack ?? error.message}`)
})

/** 设备标识与登录 Cookie 由调用方持久化，下次启动直接复用 */
interface Cache {
  ids?: Ids
  cookie?: string
  userId?: string
}

const file = new URL('./app.json', import.meta.url)
const cached: Cache = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) as Cache : {}
// App 域不依赖 web 登录：设备标识由 app.json 持久化复用，cookie 仅用于恢复上次登录态
// ids 必须在构造时传入：App 会用 ids.cookie（install_id/ttreq）初始化会话，事后 assign 会丢掉设备级 cookie
const bot = new Bot({ cookie: cached.cookie ?? '', app: { ids: cached.ids } })

const cred: CaptchaCredential = {}

// 与主循环共用同一个 readline：每建一个实例都会监听 stdin，两个实例各自回显，按键就出现两次
let rl: ReturnType<typeof createInterface>

function input (tip: string): Promise<string> {
  return rl.question(tip).then(answer => answer.trim())
}

/** 调试彩色 JSON */
function pretty (value: unknown): string {
  return (JSON.stringify(value, null, 2) ?? '')
    .replace(/"([^"]+)":/g, `\x1b[36m"$1"\x1b[0m:`)
    .replace(/: "([^"]*)"/g, `: \x1b[32m"$1"\x1b[0m`)
    .replace(/: (-?\d+(?:\.\d+)?)/g, `: \x1b[33m$1\x1b[0m`)
    .replace(/: (true|false|null)/g, `: \x1b[31m$1\x1b[0m`)
}

/** 保存设备标识与登录态，下次启动免注册/免登录 */
function save (): void {
  const { cookie, userId } = bot.app.token()
  const data: Cache = { ids: bot.app.ids, cookie }
  if (userId) data.userId = userId
  writeFileSync(file, JSON.stringify(data, null, 2))
  log.info(`状态已保存 demo/app.json uid=${userId ?? '-'}`)
}

/** 1105 滑块：起本地验证页让手机扫码拖动，通过后自动回填票据；超时再退回手动输入 */
async function captchaOf (c: Challenge): Promise<CaptchaCredential> {
  log.info(`1105 滑块: ${pretty(c)}`)
  const page = await bot.app.slide()
  if (await page.wait() && c.verifyTicket) {
    cred.verifyTicket = c.verifyTicket
    log.info('滑块通过，自动回填 verify_ticket')
    return { ...cred }
  }
  log.warn('本地验证页未通过，改为手动回填')
  const verifyTicket = await input('verify_ticket（外部验证后回填，空跳过）: ')
  const sharkTicket = await input('shark_ticket（可空）: ')
  if (verifyTicket) cred.verifyTicket = verifyTicket
  if (sharkTicket) cred.sharkTicket = sharkTicket
  return { ...cred }
}

/** 二次验证方式中文名（名称取自官方 MFA 前端 i18n） */
const WAY_ZH: Record<string, string> = {
  mobile_sms_verify: '短信验证码',
  mobile_sms_check: '短信校验',
  mobile_up_sms_verify: '短信上行验证',
  assist_up_sms_verify: '辅助短信上行验证',
  assist_sms_verify: '安全手机短信',
  face_verify: '人脸验证',
  qr_code_verify: '扫码验证',
  pwd_verify: '密码验证',
  password_verify: '密码验证',
  caijing_auth_verify: '刷脸验证',
  caijing_pwd_verify: '验证支付密码',
  caijing_bankcard_verify: '补全银行卡号',
  email_verify: '邮箱验证',
}

/** `短信验证码(mobile_sms_verify, act_type=22) 138****0000`；act_type 缺失时特别标注，避免误以为能自动完成 */
function wayLabel (w: AppWay): string {
  const raw = String(w.verify_way ?? '?')
  const act = w.act_type === undefined || w.act_type === null || w.act_type === '' ? '（无 act_type，无法自动完成）' : `, act_type=${String(w.act_type)}`
  const mobile = w.mobile ? ` ${String(w.mobile)}` : ''
  return `${WAY_ZH[raw] ?? '未知方式'}(${raw}${act})${mobile}`
}

/** 交互选择二次验证方式：返回下标，非法输入退回第一项 */
async function chooseWay (ways: AppWay[]): Promise<number> {
  log.info(`选择二次验证方式:\n${ways.map((w, i) => `  ${i + 1}. ${wayLabel(w)}`).join('\n')}`)
  const n = Number(await input(`序号（回车 = 1）: `) || 1)
  return Number.isInteger(n) && n >= 1 && n <= ways.length ? n - 1 : 0
}

/** 2046 二次验证：按选中方式给出人工输入；短信空输入 = 重新发送 */
async function ask (a: MfaAsk): Promise<string> {
  if (a.kind === 'up-sms') {
    log.info(`请用手机向 ${a.sms?.mobile ?? '-'} 发送短信: ${a.sms?.content ?? '-'}`)
    return ''
  }
  if (a.kind === 'password') return input('二次验证密码: ')
  return input(`短信验证码（${a.mobile ?? '-'}，回车重发）: `)
}

/** 终端渲染二维码并落盘，扫码内容优先取 qrcode_index_url */
async function saveQr (q: { url: string; base64?: string }): Promise<void> {
  const file = new URL('./app-qr.png', import.meta.url)
  const image = q.base64 ? Buffer.from(q.base64.replace(/^data:image\/\w+;base64,/, ''), 'base64') : undefined
  if (image) writeFileSync(file, image)
  else if (q.url) await toFile(fileURLToPath(file), q.url, { width: 300, margin: 2 })
  if (!q.url) {
    log.warn('服务端未返回二维码内容，仅保存图片 | no QR content, image saved only')
    return
  }
  const text = await qrText(q.url, { type: 'terminal', small: true, errorCorrectionLevel: 'L' })
  process.stdout.write(`\n${text}\n`)
  log.info('请用抖音 App 扫码；图片已保存 demo/app-qr.png | scan with Douyin App; image saved to demo/app-qr.png')
}

function show (r: LoginRes): void {
  const code = Number(r.data.error_code ?? 0)
  log.info(`登录${r.ok ? '成功' : '未完成'} uid=${r.userId || '-'}${code ? ` error_code=${code} ${r.data.description ?? ''}` : ''}`)
  if (r.ways?.length) log.info(`可用二次验证:\n${r.ways.map((w: AppWay) => `  - ${wayLabel(w)}`).join('\n')}`)
  if (r.ok) {
    save()
    void listen()
  }
}

/** 订阅只做一次：重登/重连时重复注册会让同一条推送打印多遍 */
let wired = false

function wire (): void {
  if (wired) return
  wired = true
  bot.app.on('message', m => log.info(`消息 conv=${m.conversationId} from=${m.senderUid} ${m.type}${m.text ? ` | ${m.text}` : ''}`))
  bot.app.on('message:edited', m => log.info(`消息编辑 conv=${m.conversationId} type=${m.type}${m.text ? ` | ${m.text}` : ''}`))
  bot.app.on('notice', n => log.info(`通知 ${n.type} ${JSON.stringify(n).slice(0, 300)}`))
  bot.app.on('request', n => log.info(`申请 ${n.type} ${JSON.stringify(n).slice(0, 300)}`))
  bot.app.on('voip', v => log.info(`来电 ${JSON.stringify(v).slice(0, 300)}`))
  bot.app.on('reconnecting', e => log.warn(`推送重连 #${e.attempt}，${e.delayMs}ms 后重试`))
  bot.app.on('close', e => log.warn(`推送断开 code=${e.code}${e.reason ? ` ${e.reason}` : ''}`))
}

/** 登录成功后自动建立 App Frontier 长连接；未登录时握手会被拒，只提示一次不反复重连 */
async function listen (): Promise<void> {
  wire()
  if (bot.app.connected) {
    log.info('推送已连接')
    return
  }
  try {
    await bot.app.start()
    log.info('推送已连接，开始接收事件（Ctrl+C 退出）')
  } catch (e) {
    log.error(`推送连接失败：${e instanceof Error ? e.message : String(e)}`)
  }
}

/** 验证码只发不登；1105 时起本地验证页，通过后自动重发 */
async function code (mobile: string): Promise<void> {
  let r = await bot.app.code(mobile, cred)
  if (r.captcha) {
    Object.assign(cred, await captchaOf(r.captcha))
    r = await bot.app.code(mobile, cred)
  }
  log.info(`验证码${r.sent ? '已发送' : '发送失败'} ${r.data.description ?? ''}`)
}

/** IM 调用：GET 直连，或按端点表加密 pb / zstd / form */
async function im (args: string[]): Promise<void> {
  if (args[0] === 'get') {
    const path = args[1]
    if (!path) {
      log.warn('用法: im get <path>')
      return
    }
    print(await bot.app.im({ path }))
    return
  }
  const name = args[0] as ImName | undefined
  if (!name) {
    log.warn('用法: im <端点名> [body] | im get <path>')
    return
  }
  const body = args.slice(1).join(' ')
  print(await bot.app.im(body ? { name, body } : { name }))
}

function print (r: Awaited<ReturnType<typeof bot.app.im>>): void {
  log.info(`HTTP ${r.status} 可解析=${r.ready}`)
  log.info(`响应:\n${pretty(r.json ?? r.text.slice(0, 2000))}`)
}

/** body 参数统一按 JSON 解析，空串给空对象 */
function json (text: string): Record<string, unknown> {
  return text ? JSON.parse(text) as Record<string, unknown> : {}
}

/** 其余业务接口的薄封装：同一入口手动验证，避免每个接口都占一条命令 */
const API: Record<string, (arg: string) => Promise<unknown>> = {
  scene: () => bot.app.scene(),
  userSettings: () => bot.app.userSettings(),
  settings: () => bot.app.settings(),
  socialSettings: () => bot.app.socialSettings(),
  compliance: () => bot.app.compliance(),
  ban: () => bot.app.ban(),
  forbid: () => bot.app.forbid(),
  dx: () => bot.app.dx(),
  notices: () => bot.app.noticeCount(),
  emoji: () => bot.app.emoji(),
  emoticon: arg => bot.app.emoticon(arg ? { keyword: arg } : undefined),
  resources: () => bot.app.resources(),
  collectFile: () => bot.app.collectFile(),
  album: () => bot.app.album(),
  recommend: () => bot.app.recommend(),
  topk: () => bot.app.topk(),
  spotlight: () => bot.app.spotlight(),
  familiar: () => bot.app.familiar(),
  localUsers: () => bot.app.localUsers(),
  center: arg => bot.app.center(json(arg)),
  chains: arg => bot.app.chains(json(arg)),
  memberSettings: arg => bot.app.memberSettings(json(arg)),
  indicators: arg => bot.app.indicators(json(arg)),
  albumAdd: arg => bot.app.albumAdd(json(arg)),
  userRecommend: arg => bot.app.userRecommend(json(arg)),
  groupNumber: arg => bot.app.groupNumber(arg),
  mixPhoto: () => bot.app.mixPhoto(),
  validate: () => bot.app.validate(),
  upgrade: () => bot.app.upgrade(),
  upgrades: () => bot.app.upgrades(),
  stranger: () => bot.app.strangerList(),
  audit: () => bot.app.auditList(),
  recent: () => bot.app.recentStranger(),
  visitors: () => bot.app.visitors(),
  videoStats: arg => bot.app.videoStats(json(arg)),
  voipColdPull: () => bot.app.voipColdPull(),
  floatingCheck: () => bot.app.floatingCheck(),
  floatingConfigs: () => bot.app.floatingConfigs(),
  backgrounds: () => bot.app.backgrounds(),
  convScene: () => bot.app.convScene(),
  convOther: arg => bot.app.convOther(json(arg)),
  openApps: arg => bot.app.openApps(json(arg)),
  foldGroups: () => bot.app.foldGroups(),
  groupTasks: () => bot.app.groupTasks(),
  groupTaskUpdate: arg => bot.app.groupTaskUpdate(json(arg)),
  groupMultiCheck: arg => bot.app.groupMultiCheck(json(arg)),
  entryLimit: () => bot.app.entryLimit(),
  groupWords: () => bot.app.groupWords(),
  imConfig: () => bot.app.imConfig(),
  globalConfig: () => bot.app.globalConfig(),
  strategyConfig: () => bot.app.strategyConfig(),
  rebootConfig: () => bot.app.rebootConfig(),
  activeConfig: () => bot.app.activeConfig(),
  activeUpdate: () => bot.app.activeUpdate(),
  activeStatus: arg => bot.app.activeStatus(json(arg)),
  enterChat: arg => bot.app.enterChat(json(arg)),
  msgTabEnter: arg => bot.app.msgTabEnter(json(arg)),
  consecutive: () => bot.app.consecutive(),
  growthShare: arg => bot.app.growthShare(json(arg)),
  consecutiveSwitch: arg => bot.app.consecutiveSwitch(json(arg)),
  consecutiveReport: arg => bot.app.consecutiveReport(json(arg)),
  growthDynamic: arg => bot.app.growthDynamic(json(arg)),
  audioModel: () => bot.app.audioModel(),
  flame: () => bot.app.flame(),
  gaga: arg => bot.app.gaga(json(arg)),
  pet: arg => bot.app.pet(json(arg)),
  petCard: () => bot.app.petCard(),
  bullet: arg => bot.app.bullet(json(arg)),
  bulletSubmit: arg => bot.app.bulletSubmit(json(arg)),
  expHit: arg => bot.app.expHit(json(arg)),
  mergePrepare: arg => bot.app.mergePrepare(json(arg)),
  commMisc: arg => bot.app.commMisc(json(arg)),
  shareReport: arg => bot.app.shareReport(json(arg)),
}

async function api (name: string | undefined, arg: string): Promise<void> {
  const fn = name ? API[name] : undefined
  if (!fn) {
    log.warn(`用法: api <${Object.keys(API).join('|')}> [json]`)
    return
  }
  log.info(`${name}:\n${pretty(await fn(arg))}`)
}

/** 命令表：语法、中文说明、English description */
const HELP: Array<[string, string, string]> = [
  ['device [force]', '注册并激活设备（每次启动自动激活），force 强制重注册', 'register & activate device (activate on startup), force to re-register'],
  ['code <mobile>', '仅发送短信验证码', 'send SMS code only'],
  ['sms <mobile>', '短信验证码登录', 'login with SMS code'],
  ['pwd <mobile>', '密码登录', 'login with password'],
  ['qr', '扫码登录，终端渲染二维码', 'QR login, render code in terminal'],
  ['mfa <kind> [input]', '手动二次验证：sms|password|upsms|qr', 'manual MFA: sms|password|upsms|qr'],
  ['info', '账号信息', 'account info'],
  ['token', '当前登录态', 'current session'],
  ['record <1|2>', '保存/清除登录信息', 'save/clear login record'],
  ['key', 'keyhub 握手并派生 IM 密钥', 'keyhub handshake & IM key'],
  ['ee', '导出 ee.info 96B key 包', 'export ee.info 96B key package'],
  ['im <name> [body]', '调用 IM 端点（自动加密）', 'call IM endpoint (auto encrypted)'],
  ['im get <path>', '自定义 GET 请求', 'custom GET request'],
  ['conv [cursor]', '会话列表（App pb）', 'conversation list (app pb)'],
  ['history <conversationId> [shortId]', '历史消息', 'chat history'],
  ['send <conversationId> <text>', '发送文本消息', 'send text message'],
  ['listen', '连接 App 推送（登录后自动连接）', 'connect App push (auto after login)'],
  ['stop', '断开 App 推送', 'disconnect App push'],
  ['self', '本人主页', 'my profile'],
  ['groups', '我加入的群列表', 'my groups'],
  ['applies', '好友申请列表', 'friend applies'],
  ['api <name> [json]', '其它业务接口，name 不带参数时打印可选列表', 'other business APIs'],
  ['state', '查看本地设备标识与登录态', 'show local device ids & session'],
  ['help', '显示本帮助', 'show this help'],
]

function helpText (): string {
  const width = Math.max(...HELP.map(([cmd]) => cmd.length))
  return HELP.map(([cmd, zh, en]) => `  ${cmd.padEnd(width)}  ${zh} | ${en}`).join('\n')
}

async function run (name: string, args: string[]): Promise<void> {
  if (name === 'device') {
    const ids = await bot.app.device({ force: args[0] === 'force' })
    log.info(`设备就绪:\n${pretty(ids)}`)
    save()
  } else if (name === 'code') {
    if (!args[0]) log.warn('用法: code <mobile>')
    else await code(args[0])
  } else if (name === 'sms') {
    if (!args[0]) {
      log.warn('用法: sms <mobile>')
      return
    }
    show(await bot.app.sms({
      mobile: args[0],
      onCode: () => input('短信验证码: '),
      onCaptcha: captchaOf,
      onMfa: ask,
      onWay: chooseWay,
    }))
  } else if (name === 'pwd') {
    if (!args[0]) {
      log.warn('用法: pwd <mobile>')
      return
    }
    const password = await input('密码: ')
    show(await bot.app.pwd({ mobile: args[0], password, onCaptcha: captchaOf, onMfa: ask, onWay: chooseWay }))
  } else if (name === 'qr') {
    show(await bot.app.qr({
      onQr: saveQr,
      onMfa: ask,
      onWay: chooseWay,
      onStatus: (s, code) => {
        log.info(`扫码状态 | status: ${s || '-'} error_code=${code || '-'}`)
        if (s === 'scanned') log.info('已扫码，请在手机上点「确认登录」| scanned, tap "Confirm" on your phone')
        if (s === 'confirmed') log.info('已确认，正在登录 | confirmed, logging in')
        if (code === 7 || code === 2156) log.info('服务端正在处理确认，继续等待 | server processing, keep waiting')
      },
    }))
  } else if (name === 'mfa') {
    const kind = (args[0] ?? '') as 'sms' | 'password' | 'upsms' | 'qr'
    if (!['sms', 'password', 'upsms', 'qr'].includes(kind)) {
      log.warn('用法: mfa sms|password|upsms|qr [input]')
      return
    }
    show(await bot.app.mfa(kind, args.slice(1).join(' ')))
  } else if (name === 'info') {
    log.info(`账号信息:\n${pretty(await bot.app.info())}`)
  } else if (name === 'token') {
    log.info(`登录态:\n${pretty(bot.app.token())}`)
  } else if (name === 'record') {
    const status = args[0] === '2' ? 2 : 1
    log.info(`保存登录信息 status=${status}:\n${pretty(await bot.app.record(status))}`)
  } else if (name === 'key') {
    log.info(`IM 密钥:\n${pretty(await bot.app.key())}`)
  } else if (name === 'ee') {
    log.info(`ee.info 条目:\n${pretty(await bot.app.ee())}`)
  } else if (name === 'im') {
    await im(args)
  } else if (name === 'conv') {
    log.info(`会话列表:\n${pretty(await bot.app.convList({ cursor: args[0] ?? 0 }))}`)
  } else if (name === 'history') {
    if (!args[0]) {
      log.warn('用法: history <conversationId> [shortId]')
      return
    }
    log.info(`历史消息:\n${pretty(await bot.app.history({ conversationId: args[0], shortId: args[1] }))}`)
  } else if (name === 'send') {
    const text = args.slice(1).join(' ')
    if (!args[0] || !text) {
      log.warn('用法: send <conversationId> <text>')
      return
    }
    log.info(`发送结果:\n${pretty(await bot.app.send({ conversationId: args[0], content: text }))}`)
  } else if (name === 'listen') {
    await listen()
  } else if (name === 'stop') {
    bot.app.stop()
    log.info('推送已断开')
  } else if (name === 'self') {
    log.info(`本人主页:\n${pretty(await bot.app.self())}`)
  } else if (name === 'groups') {
    log.info(`群列表:\n${pretty(await bot.app.groups())}`)
  } else if (name === 'applies') {
    log.info(`好友申请:\n${pretty(await bot.app.applies())}`)
  } else if (name === 'api') {
    await api(args[0], args.slice(1).join(' '))
  } else if (name === 'state') {
    log.info(`设备标识:\n${pretty(bot.app.ids)}`)
    log.info(`登录态:\n${pretty(bot.app.token())}`)
  } else if (name === 'help' || name) {
    log.info(`命令（中文 | English）:\n${helpText()}`)
  }
}

log.info(`命令（中文 | English）:\n${helpText()}`)
// 每次启动都激活：激活按启动会话校验，未激活的设备扫码确认阶段会被判 7
await bot.app.device().then(ids => {
  log.info(`设备就绪 device_id=${ids.device_id}`)
  save()
}).catch(e => {
  log.error(`设备注册/激活失败：${e instanceof Error ? e.message : String(e)}`)
})
log.info(`设备 device_id=${bot.app.ids.device_id} clientudid=${bot.app.ids.clientudid}`)
// 缓存里有登录态就顺手连推送，省去再登录一次
if (cached.cookie?.includes('sessionid=')) void listen()

rl = createInterface({ input: process.stdin, output: process.stdout, prompt: 'app> ' })
let alive = true
rl.on('close', () => {
  alive = false
})
rl.prompt()
for await (const raw of rl) {
  const [name, ...args] = raw.trim().split(/\s+/)
  try {
    await run(name, args)
  } catch (err) {
    log.error(`命令失败: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (!alive) break
  rl.prompt()
}
