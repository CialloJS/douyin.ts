/** 扫码登录对外入口:设备注册 → 取码 → 轮询 → 安全验证 / MFA → 会话。不落盘任何东西。 */
import { Http } from '../http.js'
import { passport } from '../sign/const.js'
import { createDevice } from '../device.js'
import { getQr, poll } from './poll.js'
import { warm } from './warm.js'
import { finalize } from './session.js'
import type { LoginOpts, Session } from './types.js'

export { sdkSourceInfo, signExtras } from './body.js'

/** 扫码登录全流程;调用链形态对齐 douyin-im beginLogin 桌面流程 */
export async function login (opts: LoginOpts = {}): Promise<Session> {
  const http = new Http({ userAgent: opts.userAgent ?? passport.ua, log: opts.log })
  // 服务端签发的设备身份是登录不触发短信二次验证的根因;注入已持久化身份即跳过注册
  const device = opts.device ?? await createDevice(opts.log)
  http.setDevice(device)
  await warm(http).catch(() => undefined)

  const qr = await getQr(http)
  await opts.onQr?.({ url: qr.indexUrl ?? qr.token, base64: qr.base64 })
  const session = await poll(http, qr.token, opts)
  session.device = device
  // passport 的昵称/头像是占位值,用真实资料覆盖(失败不阻断)
  return finalize(http, session)
}
