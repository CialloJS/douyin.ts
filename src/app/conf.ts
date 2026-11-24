/** 设备默认画像、公共 query 与 URL 拼装 */
import type { Dev, Ids } from './types.js'

/** 40.5.0 真机抓包默认值（清除数据全新安装的注册报文） */
export const DEV: Dev = {
  aid: 1128,
  appName: 'aweme',
  packageName: 'com.ss.android.ugc.aweme',
  versionCode: 400500,
  versionName: '40.5.0',
  manifestVersionCode: 400501,
  updateVersionCode: 40509900,
  devicePlatform: 'android',
  os: 'android',
  osApi: 37,
  osVersion: '17',
  build: 'CP2A.260605.016',
  romVersion: 'PLC110_17.0.0.100(CN01)',
  resolution: '1272*2603',
  dpi: 560,
  deviceType: 'PLC110',
  deviceBrand: 'OnePlus',
  cpuSupport64: 'true',
  hostAbi: 'arm64-v8a',
  channel: 'huawei_1128_64',
  ac: 'wifi',
  mccMnc: '46011',
  ssmix: 'a',
  appTheme: 'light',
}

export const QR_HOST = 'aweme.snssdk.com'
export const IM_HOST = 'api5-social-m-jj.amemv.com'

/** Android App UA（Cronet 版本与 40.5.0 抓包一致） */
export function ua (dev: Dev): string {
  return `com.ss.android.ugc.aweme/${dev.manifestVersionCode} (Linux; U; Android ${dev.osVersion}; zh_CN; ${dev.deviceType}; Build/${dev.build}; Cronet/TTNetVersion:295fdb87 2026-08-31 QuicVersion:462f352c 2026-08-31)`
}

/** 账户面板参数：只有 account/info、login_device/list、token/beat 这类接口带，登录接口带上会被判 7 */
const PANEL: Array<[string, string | number]> = [
  ['sec_sdk_version', 67765248],
  ['ttnet_sdk_version', '4.2.301.9-douyin'],
  ['auth_sdk_version', '4.7.7-rc.23'],
  ['account_app_language', 'zh'],
  ['verify_sdk_version', '4.2.1.cn'],
  ['multi_login', 1],
  ['account_sdk_source', 'app'],
  ['passport_support_flow', 'choose_account,captcha,real_name_check,verify'],
]

/** passport 登录类接口公共 query（真机 44 项，顺序按抓包） */
export function passportQuery (dev: Dev, ids: Partial<Ids>, extra: Record<string, string | number> = {}): URLSearchParams {
  const q = new URLSearchParams()
  const base: Array<[string, string | number]> = [
    ['passport-sdk-version', 60755],
    ['request_from_account_sdk', 1],
    ['is_from_ttaccountsdk', 1],
    ['language', 'zh'],
    ['aid', dev.aid],
    ['app_name', dev.appName],
    ['version_code', dev.versionCode],
    ['version_name', dev.versionName],
    ['manifest_version_code', dev.manifestVersionCode],
    ['update_version_code', dev.updateVersionCode],
    ['device_platform', dev.devicePlatform],
    ['os', dev.os],
    ['os_api', dev.osApi],
    ['os_version', dev.osVersion],
    ['ssmix', dev.ssmix],
    ['channel', dev.channel],
    ['ac', dev.ac],
    ['mcc_mnc', dev.mccMnc],
    ['resolution', dev.resolution],
    ['dpi', dev.dpi],
    ['device_type', dev.deviceType],
    ['device_brand', dev.deviceBrand],
    ['cpu_support64', dev.cpuSupport64],
    ['host_abi', dev.hostAbi],
    ['package', dev.packageName],
    ['appTheme', dev.appTheme],
    ['use_store_region_cookie', 1],
  ]
  for (const [k, v] of base) q.append(k, String(v))
  idQuery(q, ids)
  for (const [k, v] of Object.entries(extra)) q.set(k, String(v))
  return q
}

/** IM / 通用 API 公共 query（缺字段或身份不一致会返回 3105） */
export function socialQuery (dev: Dev, ids: Partial<Ids>, extra: Record<string, string | number> = {}): URLSearchParams {
  const q = new URLSearchParams()
  const base: Array<[string, string | number]> = [
    ['ac', dev.ac],
    ['channel', dev.channel],
    ['aid', dev.aid],
    ['app_name', dev.appName],
    ['version_code', dev.versionCode],
    ['version_name', dev.versionName],
    ['device_platform', dev.devicePlatform],
    ['os', dev.os],
    ['ssmix', dev.ssmix],
    ['device_type', dev.deviceType],
    ['device_brand', dev.deviceBrand],
    ['language', 'zh'],
    ['os_api', dev.osApi],
    ['os_version', dev.osVersion],
    ['manifest_version_code', dev.manifestVersionCode],
    ['resolution', dev.resolution],
    ['dpi', dev.dpi],
    ['update_version_code', dev.updateVersionCode],
    ['package', dev.packageName],
    ['mcc_mnc', dev.mccMnc],
    ['first_launch_timestamp', ids.first_install ?? ''],
    ['last_deeplink_update_version_code', 0],
    ['cpu_support64', dev.cpuSupport64],
    ['host_abi', dev.hostAbi],
    ['is_guest_mode', 0],
    ['app_type', 'normal'],
    ['minor_status', 0],
    ['appTheme', dev.appTheme],
    ['is_preinstall', 0],
    ['need_personal_recommend', 1],
    ['is_android_pad', 0],
    ['is_android_fold', 0],
  ]
  for (const [k, v] of base) if (String(v) !== '') q.append(k, String(v))
  idQuery(q, ids)
  for (const [k, v] of Object.entries(extra)) q.set(k, String(v))
  return q
}

function idQuery (q: URLSearchParams, ids: Partial<Ids>): void {
  const pairs: Array<[string, string | undefined]> = [
    ['device_id', ids.device_id],
    ['iid', ids.iid],
    ['cdid', ids.cdid],
    ['klink_egdi', ids.klink_egdi],
  ]
  for (const [k, v] of pairs) if (v) q.append(k, v)
}

/** 账户面板接口：在登录 query 上追加面板参数，scene 真机取 normal */
export function panelQuery (q: URLSearchParams, scene = 'normal'): URLSearchParams {
  const out = new URLSearchParams(q)
  for (const [k, v] of PANEL) out.append(k, String(v))
  out.append('is_from_iesaccountsaas', '1')
  out.append('scene', scene)
  return out
}

export interface Time {
  /** 秒 */
  ts?: number
  /** 毫秒 */
  rticket?: number
}

export function nowTime (): Required<Time> {
  const ms = Date.now()
  return { ts: Math.floor(ms / 1000), rticket: ms }
}

/** 重写动态时间参数，避免重复 */
export function buildUrl (host: string, path: string, params: URLSearchParams, t: Time = {}): string {
  const q = new URLSearchParams(params)
  for (const k of ['_rticket', 'ts']) q.delete(k)
  const { ts, rticket } = { ...nowTime(), ...t }
  q.append('_rticket', String(rticket))
  q.append('ts', String(ts))
  return `https://${host}${path}?${q.toString()}`
}
