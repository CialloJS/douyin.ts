/** 验证组件准备:平台判定与两种组件形态的配置组装 */
import { err } from '../../error.js'
import { randomHex } from '../sign/qs.js'
import { im } from '../sign/const.js'
import { host as domain, vc } from '../login/codes.js'
import type { Http } from '../http.js'
import type { Decision, Hooks, Prepared } from './types.js'
import { asRecord } from './json.js'
import { captchaOptions, loadSetting, packWays, scriptsOf } from './center.js'

/**
 * 网页登录与桌面 IM 的验证服务 host 不同,SDK 用 host 拼相对路径;
 * 用表驱动而不是 if,新增客户端场景只加一行。
 */
const PLATFORM = [
  { aid: vc.webAid, host: `https://${domain.web}`, appName: '抖音 Web 站' },
  { aid: Number(im.aid), host: `https://${domain.im}`, appName: '抖音聊天' },
] as const

export async function prepare (http: Http, descriptor: Decision, hooks: Hooks): Promise<Prepared> {
  const decisionAid = Number(asRecord(descriptor.decision)?.['aid'] ?? 0)
  const aid = hooks.aid ?? (decisionAid > 0 ? decisionAid : Number(im.aid))
  const platform = PLATFORM.find(item => item.aid === aid) ?? PLATFORM[1]
  const deviceId = deviceOf(http)
  let config = { ...descriptor.decision }
  const verifyFrom = String(config['verify_from'] ?? '')
  // VerifyCenter 按 code 分发,不是 verify_from 字符串;先按 code 判定可避免多打一次 pack 接口
  const byCode = vc.codes.includes(Number(config['code']))
  if (!byCode && verifyFrom === vc.from) {
    config = { ...config, ...(await packWays(http, config, deviceId, aid)) }
  }
  const base = {
    config,
    fp: `${vc.fpPrefix}${deviceId}`,
    deviceId,
    aid,
    host: hooks.host ?? platform.host,
    appName: platform.appName,
  }
  if (byCode) {
    const setting = await loadSetting(http, deviceId, aid)
    const scene = captchaOptions(config)
    return {
      ...base,
      config: { ...config, scene_level: scene.scene },
      mode: 'verify-center',
      scripts: scriptsOf(setting),
      options: scene.options,
    }
  }
  const rawUrl = typeof config['url'] === 'string' ? config['url'] : undefined
  // 真实客户端的 SecondVerify SDK 内置在客户端,决策 url 只是可选的动态版本
  if (!rawUrl) return { ...base, mode: 'second-verify' }
  const script = new URL(rawUrl)
  if (script.protocol !== 'https:') {
    err({ protocol: script.protocol })
  }
  script.searchParams.set('aid', String(aid))
  const event = asRecord(config['event_params'])
  script.searchParams.set('verify_reason', String(event?.['verify_reason'] ?? ''))
  script.searchParams.set('verify_scene', String(event?.['verify_scene'] ?? ''))
  return { ...base, mode: 'second-verify', script: script.toString() }
}

/** 对齐 douyin-im:验证组件复用连接上已注册的设备身份,无注册设备才回退随机 hex */
function deviceOf (http: Http): string {
  return http.hasDevice() ? http.deviceId : randomHex(16)
}
