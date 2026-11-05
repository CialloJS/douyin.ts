import { cmd, site } from '../session/codes.js'
import { im, mac } from '../session/sign/const.js'

/** 桌面 IM 客户端 UA（媒体上传与 Cookie 通道共用，macOS 口径） */
export const PC_UA = mac.ua

/** 桌面身份元信息：三处 query/header 共用，避免版本号互不一致触发风控 */
const deskMeta = {
  appId: 339757,
  appName: 'aweme_im_desktop',
  version: im.version,
} as const

/** 安卓端常量（WS 通道 cmd411 envelope 用；握手常量见 link.ts） */
export const android = {
  aid: '1128',
  versionCode: '280400',
  channel: 'douyinweb1_64',
  deviceType: '24031PN0DC',
  osVersion: '14',
  appName: 'aweme',
  buildNumber: '5030',
  biz: 'douyin',
  access: 'douyin_main',
} as const

export const ANDROID_UA = cmd.ua
export const ANDROID_SDK_VERSION = cmd.sdk

/** config/v2 与 batch_play_info 共用的桌面指纹 query（媒体上传用） */
export function fingerprintParams (deviceId: string, guid: string): URLSearchParams {
  return new URLSearchParams({
    aid: String(deskMeta.appId),
    version_name: deskMeta.version,
    version_code: deskMeta.version,
    device_platform: mac.platform,
    os_version: mac.release,
    screen_width: mac.width,
    screen_height: mac.height,
    browser_language: 'zh-CN',
    browser_platform: mac.browserPlatform,
    browser_name: mac.browserName,
    browser_version: PC_UA.replace(/^Mozilla\//, ''),
    browser_online: 'true',
    cookie_enabled: 'true',
    device_id: deviceId,
    did: deviceId,
    iid: '0',
    awemeim_guid: guid,
    channel: mac.channel,
  })
}

/** 官方桌面客户端 queryMap（设备身份载体；native ImOption.headersMap 为空） */
function imQuery (deviceId: string): Record<string, string> {
  return {
    aid: String(deskMeta.appId),
    app_name: deskMeta.appName,
    did: deviceId,
    device_id: deviceId,
    iid: '0',
    channel: mac.channel,
    os_version: mac.release,
    version_code: deskMeta.version,
    version_name: deskMeta.version,
    device_platform: 'mac',
    device_type: process.arch,
    device_brand: '',
  }
}

/** 原生通道 f15 headers map（设备身份载体） */
function nativeHeaders (deviceId: string): Record<string, string> {
  return {
    session_aid: String(deskMeta.appId),
    session_did: deviceId,
    app_name: 'douyin_pc',
    priority_region: 'cn',
    user_agent: PC_UA,
    cookie_enabled: 'true',
    browser_language: 'zh-CN',
    browser_platform: mac.browserPlatform,
    browser_name: mac.browserName,
    browser_version: PC_UA.replace(/^Mozilla\//, ''),
    browser_online: 'true',
    screen_width: mac.width,
    screen_height: mac.height,
    referer: '',
    timezone_name: 'Asia/Shanghai',
    'is-retry': '0',
  }
}

/** cmd411 内层 envelope f15 headers KV（设备身份载体） */
export function androidHeaders (uid: string): [string, string][] {
  return [
    ['app_name', android.appName], ['iid', uid], ['version_code', android.versionCode],
    ['net_mcc_mnc', '46000'], ['aid', android.aid], ['flow-tag', 'new'], ['user-agent', ANDROID_UA],
  ]
}

/** HTTP protobuf 通道 profile：只描述地址/身份/请求头差异，发送流程共用 */
export interface Channel {
  url(endpoint: string, deviceId: string): string
  headers(deviceId: string): Record<string, string>
  sdkVersion: string
  buildNumber: string
  versionCode: string
  devicePlatform: string
  biz: string
  access: string
  accept: string
  /** true 时携带请求体 MD5（x-ss-stub） */
  stub: boolean
}

/** Desktop Cookie 通道（对照官方 native ImOption：设备身份走 URL query 而非 envelope headers） */
export const desk: Channel = {
  url: (endpoint, deviceId) => {
    const url = new URL(endpoint, site.apiAlt)
    for (const [key, value] of Object.entries(imQuery(deviceId))) url.searchParams.set(key, value)
    return url.toString()
  },
  headers: () => ({}),
  sdkVersion: deskMeta.version,
  buildNumber: 'eb11b84dd0eb26ae22321b53426d3f976b920862',
  versionCode: deskMeta.version,
  devicePlatform: 'mac',
  biz: 'douyin_im_pc',
  access: 'cpp_sdk',
  accept: 'x-protobuf',
  stub: true,
}

/** 原生通道（对照 HAR：无 URL query、无 x-ss-stub；设备身份走 envelope f15 headers map） */
export const native: Channel = {
  url: (endpoint, _deviceId) => `${site.api}${endpoint}`,
  headers: nativeHeaders,
  sdkVersion: '0.1.8',
  buildNumber: '0d50935:feat/pc-im-group',
  versionCode: '360000',
  devicePlatform: 'douyin_pc',
  biz: 'douyin_im_pc',
  access: 'web_sdk',
  accept: 'application/x-protobuf',
  stub: false,
}
