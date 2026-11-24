/** App 会话：cookie jar + 响应头回带的 token / MFA 票据 */
import { randomBytes, randomUUID } from 'node:crypto'
import { Jar } from '../session/jar.js'

const TOKENS = ['x-tt-token', 'x-tt-token-supplement', 'token-tlb-tag', 'session-tlb-tag']

export class Auth {
  readonly jar: Jar
  tokens: Record<string, string> = {}
  /** x-tt-passport-verify-portrait 每次会话随机 */
  portrait = `${randomUUID()}.login`
  traceId = `login_${randomBytes(16).toString('hex')}`
  lastHeaders: Record<string, string> = {}
  /** 2046 凭据：服务端靠它把「验证通过」关联到待登录会话 */
  mfaToken = ''
  /** 设备票据，响应头 d-ticket 下发 */
  dTicket = ''
  /** 本次 MFA 实际通过的验证方式（重放时 echo 到 std_verify_way） */
  verifiedWay = ''
  /** ticket-guard 短时票据：boot 响应头下发，业务请求缺它会被判未提供设备证明 */
  sec = ''
  secAt = 0
  /** odin_tt 有效期约 31s，按同样节奏刷新预热 */
  warmAt = 0

  constructor (cookie?: string) {
    this.jar = new Jar(cookie)
    this.seed()
  }

  /** 真机 passport 会话的 csrf 由客户端自生成，每个 passport 请求都会带；缺了服务端按系统繁忙兜底 */
  private seed (): void {
    if (this.jar.get('passport_csrf_token')) return
    const v = randomBytes(16).toString('hex')
    this.jar.merge(`passport_csrf_token=${v}; passport_csrf_token_default=${v}`)
  }

  cookie (): string {
    // 本机没有同源 ticket-guard 密钥，不能声明「已设置公钥」：声明了服务端就会强制校验，缺失即判 7
    return this.jar.header()
      .split('; ')
      .filter(kv => !kv.startsWith('ticket_guard_has_set_public_key='))
      .join('; ')
  }

  /** 二维码是独立会话：重新取码前清空上一轮 cookie/token，否则服务端按系统繁忙兜底 */
  reset (): void {
    this.jar.clear()
    this.seed()
    this.tokens = {}
    this.portrait = `${randomUUID()}.login`
    this.traceId = `login_${randomBytes(16).toString('hex')}`
    this.lastHeaders = {}
    this.mfaToken = ''
    this.dTicket = ''
    this.verifiedWay = ''
    this.sec = ''
    this.secAt = 0
    this.warmAt = 0
  }

  absorb (setCookie: string[]): void {
    for (const line of setCookie) this.jar.absorb(line)
  }

  csrf (): string | undefined {
    return this.jar.get('passport_csrf_token')
  }

  get sessionid (): string | undefined {
    const sid = this.jar.get('sessionid')
    return sid && sid !== 'undefined' ? sid : undefined
  }

  take (headers: Record<string, string>): void {
    for (const n of TOKENS) {
      const v = headers[n] ?? headers[n.toLowerCase()]
      if (v) this.tokens[n] = v
    }
    const mfa = headers['x-tt-passport-mfa-token']
    if (mfa) this.mfaToken = mfa
    const dt = headers['d-ticket'] ?? headers['d_ticket']
    if (dt) this.dTicket = dt
  }
}
