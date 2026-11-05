/** 验证中心配置换取:把决策换成动态脚本地址与 captcha 业务参数 */
import { err } from '../../error.js'
import { form } from '../lite.js'
import { im, mac } from '../sign/const.js'
import { fld, path, vc } from '../login/codes.js'
import type { Http } from '../http.js'
import { asRecord, encodeField, tryParse } from './json.js'
import { requestRaw } from './proxy.js'

/**
 * verify_center 决策只带业务意图,组件脚本与 scene_level 要从 vcs 拉取;
 * is_login 由服务端自行推导,回传会被判定参数错误。
 */
export async function packWays (
  http: Http,
  decision: Record<string, unknown>,
  deviceId: string,
  aid: number,
): Promise<Record<string, unknown>> {
  const body: Record<string, string> = {}
  const requestData: Record<string, unknown> = {
    aid,
    ...decision,
    device_id: deviceId,
    iid: fld.iid,
    version_code: im.version,
    device_platform: mac.platform,
  }
  for (const [key, value] of Object.entries(requestData)) {
    if (key === 'is_login' || value == null) continue
    body[key] = encodeField(value)
  }
  const res = await form(http, path.pack, body)
  if (res.data.error_code != null && res.data.error_code !== 0) err(res)
  return res.data
}

/** 配置拉取失败不阻断:内置官方 SDK 地址仍可完成验证 */
export async function loadSetting (http: Http, deviceId: string, aid: number): Promise<Record<string, unknown> | undefined> {
  try {
    const query = new URLSearchParams({ aid: String(aid), did: deviceId || fld.iid, iid: fld.iid })
    const res = await requestRaw(http, `${vc.setting}?${query}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Setting-Flag': vc.flag },
      body: '{}',
    })
    if (!res.ok) return undefined
    const parsed = asRecord(tryParse(res.text))
    const data = asRecord(parsed?.['data']) ?? parsed
    return asRecord(data?.['verify'])
  } catch {
    return undefined
  }
}

/** 配置里的脚本地址按优先级拼接,内置地址永远兜底 */
export function scriptsOf (setting: Record<string, unknown> | undefined): string[] {
  const primary = asRecord(setting?.['js_v2'])?.['cn']
  const backups = asRecord(setting?.['back_up_js_v2'])?.['cn']
  const urls = [
    ...(typeof primary === 'string' ? [primary] : []),
    ...(Array.isArray(backups)
      ? backups.filter((value): value is string => typeof value === 'string')
      : []),
    vc.center,
    ...vc.centerBackups,
  ]
  return [...new Set(urls)]
}

/** 官方成功链路 captcha/get 必带这些参数,缺失返回 501 */
export function captchaOptions (config: Record<string, unknown>): { scene: string; options: Record<string, unknown> } {
  const scene = config['scene_level'] == null || config['scene_level'] === ''
    ? vc.scene
    : String(config['scene_level'])
  return {
    scene,
    options: {
      repoId: vc.repo,
      h5_check_version: vc.h5,
      extraConfig: vc.extra,
      scene_level: scene,
    },
  }
}
