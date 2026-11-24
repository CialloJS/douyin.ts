/** bdturing 静默采集：服务端回 40000/nocaptcha_collect 时，按真机算法上报后重试原请求 */
import { createCipheriv, createHash, randomInt } from 'node:crypto'
import { createLog } from '../session/log.js'
import type { Auth } from './auth.js'
import type { Dev, Ids } from './types.js'
import { request, type Res } from './http.js'
import { ua } from './conf.js'
import { dtrait } from './dtrait.js'
import { soSign } from './so/index.js'

const log = createLog({ tag: 'turing' })
const HOST = 'verify-zjg.zijieapi.com'
/** 进程启动时刻：上报里的 launch_time/runtime 以它为基准 */
const START = Date.now()
const PAGE = 'com.ss.android.ugc.aweme.main.MainActivity'
/** 服务端下发的采集开关，样本各字段恒为 true */
const CONF = {
  async_collect_time_out: 10000,
  collect_page_history: true,
  collect_page_history_pre: true,
  collect_touch_event: true,
  collect_touch_event_pre: true,
  report_time_out: 2000,
  trigger_sec_sdk: true,
  use_static_touch_proxy: true,
}
const ALPHA = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

export interface Ask {
  subtype: string
  detail: string
  logId: string
}

/**
 * 只处理静默采集；10000 属于滑块，交给调用方。
 * 40000 实测只在 x-vc-bdturing-parameters 里下发（bdturing-verify 是同一响应里的滑块决策），
 * 漏读它等于跳过环境采集，后续 verify 会被判 5014。
 */
export function ask (res: Res): Ask | undefined {
  for (const name of ['bdturing-verify', 'x-vc-bdturing-parameters']) {
    const raw = res.headers[name]
    if (!raw) continue
    try {
      const j = JSON.parse(raw) as Record<string, unknown>
      if (String(j.code) !== '40000' || String(j.type) !== 'verify') continue
      const detail = String(j.detail ?? '')
      if (!detail) continue
      return { subtype: String(j.subtype ?? ''), detail, logId: String(j.log_id ?? '') }
    } catch {
      // 另一个头可能才是采集决策，继续找
    }
  }
  return undefined
}

/** 上报体：真机字段齐全，但触摸轨迹为空（无 UI，服务端只做存在性判断） */
function body (a: Ask): string {
  const now = Date.now()
  return JSON.stringify({
    data_type: 'async_collect',
    common: {
      launch_time: START,
      is_back_ground: false,
      runtime: now - START,
      page_id: PAGE,
      page_history: [{ id: PAGE, et: START, lt: 0 }],
      page_profile: [{ index: 0, ts: START, name: PAGE, touch_hook: { success: 1, ts: START } }],
      first_touch_event: [],
      touch_event: [],
    },
    data_profile: { page_history_count: 1, touch_event_count: 0, first_touch_event_count: 0, page_profile_count: 1 },
    sdk_runtime_info: {
      init_pid: process.pid,
      pid: process.pid,
      init_time: START,
      life_cycle_register_time: START,
      th_init_ts: START,
      th_init_result: true,
      th_init_page_id: PAGE,
    },
    nocaptcha: CONF,
    async_collect_data: { async_touch_event_start_time: now },
    status_code: 0,
    log_ids: a.logId ? [a.logId] : [],
  })
}

/** 09eh：tc 信封 + 随机 nonce + AES-256-GCM，密钥由 nonce 与 detail 的 MD5 双层 SHA512 派生 */
function seal (text: string, detail: string): string {
  let nonce = ''
  for (let i = 0; i < 32; i++) nonce += ALPHA[randomInt(ALPHA.length)]
  const md5 = createHash('md5').update(detail).digest()
  const seed = createHash('sha512').update(Buffer.concat([createHash('sha512').update(nonce).digest(), md5])).digest()
  const cipher = createCipheriv('aes-256-gcm', seed.subarray(0, 32), seed.subarray(32, 44))
  const plain = Buffer.concat([createHash('sha512').update(text).digest(), Buffer.from(text)])
  const enc = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()])
  return Buffer.concat([Buffer.from([0x74, 0x63, 6, 16, 0, 0]), Buffer.from(nonce), enc]).toString('base64')
}

function query (a: Ask, dev: Dev, ids: Ids): URLSearchParams {
  const q = new URLSearchParams()
  const base: Array<[string, string]> = [
    ['app_version', dev.versionName],
    ['device_model', dev.deviceType],
    ['iid', ids.iid ?? ''],
    ['channel', dev.channel],
    ['device_type', dev.deviceType],
    ['locale', 'zh_CN'],
    ['resolution', dev.resolution],
    ['subtype', a.subtype],
    ['sdk_version', '4.2.1.cn'],
    ['lang', 'zh'],
    ['orientation', '2'],
    ['ch', dev.channel],
    ['os_version', dev.osVersion],
    ['version_code', String(dev.manifestVersionCode)],
    ['vc', dev.versionName],
    ['app_name', dev.appName],
    ['app_key', ''],
    ['version_name', dev.versionName],
    ['device_brand', dev.deviceBrand],
    ['os_type', '0'],
    ['os_name', 'android'],
    ['device_platform', dev.devicePlatform],
    ['detail', a.detail],
    ['region', 'cn'],
    ['aid', String(dev.aid)],
    ['did', ids.device_id ?? ''],
  ]
  for (const [k, v] of base) q.append(k, v)
  const ms = Date.now()
  q.append('_rticket', String(ms))
  q.append('ts', String(Math.floor(ms / 1000)))
  return q
}

export async function report (a: Ask, dev: Dev, ids: Ids, auth: Auth): Promise<boolean> {
  const url = `https://${HOST}/nocaptcha/report?${query(a, dev, ids).toString()}`
  const headers: Array<[string, string]> = [
    ['user-agent', ua(dev)],
    ['x-ss-dp', String(dev.aid)],
    ['x-tt-request-tag', 'n=1;t=0;s=1;p=0'],
    ['x-bd-kmsv', '1'],
    ['x-vc-bdturing-sdk-version', '4.2.1.cn'],
    ['content-type', 'application/json; charset=utf-8'],
    ['accept-encoding', 'gzip, deflate, br'],
  ]
  const cookie = auth.cookie()
  if (cookie) headers.push(['cookie', cookie])
  if (ids.device_id) {
    const dt = dtrait(ids)
    if (dt.payload) {
      headers.push(['x-tt-device-dtrait', dt.payload])
      headers.push(['x-tt-device-signal', dt.signal])
      headers.push(['x-bb-signal', dt.signal])
      headers.push(['x-bb-scene', dt.scene])
    }
    // 只带 x-bb-data：该接口不走 passport 通道，其余会话头无意义
    if (dt.data) headers.push(['x-bb-data', dt.data])
  }
  for (const [k, v] of Object.entries(soSign(url, undefined, { deviceId: ids.device_id, installId: ids.iid }))) {
    headers.push([k, v])
  }
  try {
    const res = await request({ url, method: 'POST', headers, body: Buffer.from(JSON.stringify({ data: seal(body(a), a.detail) })) })
    const ok = Number((res.json as { code?: number } | undefined)?.code ?? 0) === 200
    if (ok) log.info('静默采集已上报')
    else log.warn(`静默采集失败 status=${res.status} ${res.text.slice(0, 120)}`)
    return ok
  } catch (err) {
    log.warn(`静默采集异常 ${(err as Error).message}`)
    return false
  }
}
