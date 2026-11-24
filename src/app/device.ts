/** 设备注册 + 激活：刷新失效设备凭据（passport 报 7 的系统繁忙多因凭据失效） */
import { randomUUID } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import type { Ids } from './types.js'
import { request } from './http.js'
import { ssStub } from './codec.js'
import { ttEncrypt } from './crypt.js'
import { strip, type HeaderPair } from './sign/index.js'
import { soSign } from './so/index.js'
import { fill } from './ids.js'
import { boot } from './api.js'
import { Auth } from './auth.js'
import { regHead } from './guard.js'
import { DEV, ua } from './conf.js'
import { Jar } from '../session/jar.js'

/** 真机注册走 log.snssdk.com，激活走 klink；两者下发的设备级 cookie 不同 */
const REG_HOST = 'https://log.snssdk.com'
const ACT_HOST = 'https://klink.amemv.com'
const REG_PATH = '/service/2/device_register/'
const ACT_PATH = '/service/2/app_alert_check/'

/** 注册与登录必须共用同一套画像：服务端按 device_id 记住注册画像，登录时不一致会在扫码确认阶段判 7 */
const APP = {
  aid: String(DEV.aid),
  appName: DEV.appName,
  pkg: DEV.packageName,
  versionCode: String(DEV.versionCode),
  versionName: DEV.versionName,
  manifestVersionCode: String(DEV.manifestVersionCode),
  updateVersionCode: String(DEV.updateVersionCode),
  osVersion: DEV.osVersion,
  osApi: String(DEV.osApi),
  build: DEV.build,
  romVersion: DEV.romVersion,
  deviceType: DEV.deviceType,
  deviceBrand: DEV.deviceBrand,
  hostAbi: DEV.hostAbi,
  resolution: DEV.resolution,
  dpi: String(DEV.dpi),
  channel: DEV.channel,
  mccMnc: DEV.mccMnc,
} as const

const UA = ua(DEV)

const SDK_VERSION = '3.7.3-rc.116-douyin'
/** APK 签名证书 MD5，同版本恒定 */
const SIG_HASH = 'aea615ab910015038f73c47e45d21466'

export interface DevOpts {
  host?: string
  /** 注册后是否激活，默认 true */
  activate?: boolean
  timeoutMs?: number
}

interface Reg {
  openudid: string
  cdid: string
  clientudid: string
  req_id: string
  oaid: string
  firstInstall: number
}

/** 注册上报的装机时间必须与后续查询里的 first_launch_timestamp 完全一致 */
function regOf (ids: Ids): Reg {
  const now = Math.floor(Date.now() / 1000)
  return {
    openudid: ids.openudid,
    cdid: ids.cdid,
    clientudid: ids.clientudid,
    req_id: ids.req_id,
    oaid: ids.oaid,
    firstInstall: ids.first_install || now - 7 * 86400,
  }
}

function traceId (): string {
  return `00-${randomUUID().replace(/-/g, '')}-${randomUUID().replace(/-/g, '').slice(0, 16)}-01`
}

function regQuery (dev: Reg, ms: number): Array<[string, string]> {
  const now = Math.floor(ms / 1000)
  return [
    ['ac', 'wifi'],
    ['channel', APP.channel],
    ['aid', APP.aid],
    ['app_name', APP.appName],
    ['version_code', APP.versionCode],
    ['version_name', APP.versionName],
    ['device_platform', 'android'],
    ['os', 'android'],
    ['ssmix', 'a'],
    ['device_type', APP.deviceType],
    ['device_brand', APP.deviceBrand],
    ['language', 'zh'],
    ['os_api', APP.osApi],
    ['os_version', APP.osVersion],
    ['manifest_version_code', APP.manifestVersionCode],
    ['resolution', APP.resolution],
    ['dpi', APP.dpi],
    ['update_version_code', APP.updateVersionCode],
    ['_rticket', String(ms)],
    ['package', APP.pkg],
    ['mcc_mnc', APP.mccMnc],
    ['first_launch_timestamp', String(dev.firstInstall)],
    ['last_deeplink_update_version_code', '0'],
    ['cpu_support64', 'true'],
    ['host_abi', APP.hostAbi],
    ['is_guest_mode', '0'],
    ['app_type', 'normal'],
    ['minor_status', '0'],
    ['appTheme', 'light'],
    ['is_preinstall', '0'],
    ['need_personal_recommend', '1'],
    ['is_android_pad', '0'],
    ['is_android_fold', '0'],
    ['md', '0'],
    ['cdid', dev.cdid],
    ['cronet_version', '295fdb87_2026-08-31'],
    ['ttnet_version', '4.2.301.9-douyin'],
    ['use_store_region_cookie', '1'],
    ['ts', String(now)],
  ]
}

function actQuery (dev: Reg, ms: number): Array<[string, string]> {
  const now = Math.floor(ms / 1000)
  return [
    ['aid', APP.aid],
    ['app_name', APP.appName],
    ['package', APP.pkg],
    ['version_code', APP.versionCode],
    ['version_name', APP.versionName],
    ['manifest_version_code', APP.manifestVersionCode],
    ['update_version_code', APP.updateVersionCode],
    ['device_platform', 'android'],
    ['os', 'android'],
    ['ssmix', 'a'],
    ['ac', 'wifi'],
    ['channel', APP.channel],
    ['device_type', APP.deviceType],
    ['device_brand', APP.deviceBrand],
    ['os_api', APP.osApi],
    ['os_version', APP.osVersion],
    ['language', 'zh'],
    ['resolution', APP.resolution],
    ['dpi', APP.dpi],
    ['openudid', dev.openudid],
    ['cdid', dev.cdid],
    ['clientudid', dev.clientudid],
    ['cpu_support64', 'true'],
    ['host_abi', APP.hostAbi],
    ['is_guest_mode', '0'],
    ['app_type', 'normal'],
    ['minor_status', '0'],
    ['appTheme', 'light'],
    ['is_preinstall', '0'],
    ['need_personal_recommend', '1'],
    ['is_android_pad', '0'],
    ['is_android_fold', '0'],
    ['timezone', '8'],
    ['custom_bt', '1'],
    ['req_id', dev.req_id],
    ['ts', String(now)],
    ['_rticket', String(ms)],
  ]
}

/** ss_app_log 结构 */
function regBody (dev: Reg): string {
  const now = Date.now()
  const header = {
    display_name: '抖音',
    update_version_code: Number(APP.updateVersionCode),
    manifest_version_code: Number(APP.manifestVersionCode),
    app_version_minor: '',
    aid: Number(APP.aid),
    channel: APP.channel,
    package: APP.pkg,
    app_version: APP.versionName,
    version_code: Number(APP.versionCode),
    sdk_version: SDK_VERSION,
    sdk_target_version: 29,
    git_hash: 'fe95b95',
    os: 'Android',
    os_version: APP.osVersion,
    os_api: Number(APP.osApi),
    device_model: APP.deviceType,
    device_brand: APP.deviceBrand,
    device_manufacturer: APP.deviceBrand,
    device_category: 'phone',
    cpu_abi: APP.hostAbi,
    release_build: APP.build,
    density_dpi: Number(APP.dpi),
    display_density: 'xxxhdpi',
    resolution: APP.resolution.split('*').reverse().join('x'),
    language: 'zh',
    timezone: 8,
    access: 'wifi',
    not_request_sender: 0,
    carrier: '',
    mcc_mnc: APP.mccMnc,
    rom: 'V17.0.0',
    rom_version: APP.romVersion,
    cdid: dev.cdid,
    sig_hash: SIG_HASH,
    openudid: dev.openudid,
    clientudid: dev.clientudid,
    ipv6_list: [],
    region: 'CN',
    tz_name: 'Asia/Shanghai',
    tz_offset: 28800,
    sim_region: 'cn',
    sim_serial_number: [],
    oaid: {
      req_id: randomUUID(),
      hw_id_version_code: 'null',
      take_ms: '0',
      is_track_limited: 'true',
      query_times: '1',
      id: dev.oaid,
      time: String(now),
    },
    oaid_may_support: true,
    req_id: dev.req_id,
    device_platform: 'android',
    pre_installed_channel: '',
    apk_first_install_time: dev.firstInstall * 1000,
    is_system_app: 0,
    sdk_flavor: 'china',
    guest_mode: 0,
  }
  return JSON.stringify({ magic_tag: 'ss_app_log', header, _gen_time: now })
}

function head (ms: number, stub?: string, extra: HeaderPair[] = []): HeaderPair[] {
  const list: HeaderPair[] = [
    ['content-type', 'application/json; charset=utf-8'],
    ['accept-encoding', 'gzip, deflate, br'],
    ['log-encode-type', 'gzip'],
    ['x-ss-dp', APP.aid],
    ['x-tt-request-tag', 't=0;n=1;s=0;p=0'],
    ['activity_now_client', String(ms)],
    ['x-ss-req-ticket', String(ms)],
    ['sdk-version', '2'],
    ['passport-sdk-settings', 'device_transfer_s_0,device_transfer_ab_0'],
    ['passport-sdk-version', '60755'],
    ['x-vc-bdturing-sdk-version', '4.2.1.cn'],
    ['x-tt-trace-id', traceId()],
    ['user-agent', UA],
  ]
  if (stub) list.push(['x-ss-stub', stub])
  return list.concat(extra)
}

function qs (list: Array<[string, string]>): string {
  return list.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')
}

async function reg (base: Ids, opts: DevOpts): Promise<Ids> {
  const host = (opts.host ?? REG_HOST).replace(/\/$/, '')
  const dev = regOf(base)
  // 真机注册同样带设备证明：服务端据此把公钥绑定到 device_id，后续业务请求才认 static-sign
  const sec = await boot(new Auth(), DEV, base)
  const ms = Date.now()
  // 40.5.0 注册体是 ttEncrypt(gzip(json))，明文 JSON 会被当成旧版客户端、不下发 store-region/ttreq
  const body = ttEncrypt(gzipSync(Buffer.from(regBody(dev), 'utf8')))
  const url = `${host}${REG_PATH}?${qs([['tt_data', 'a'], ...regQuery(dev, ms)])}`
  const csrf = randomUUID().replace(/-/g, '')
  const headers = strip(
    head(ms, ssStub(body))
      .map(([k, v]) => (k === 'content-type' ? [k, 'application/octet-stream;tt-data=a'] : [k, v]) as HeaderPair)
      .concat([['cookie', `passport_csrf_token=${csrf}; passport_csrf_token_default=${csrf}`]])
      .concat(sec ? regHead(base, sec) : []),
  )
  const sig = soSign(url, new Uint8Array(body))
  const res = await request({
    url,
    method: 'POST',
    headers: [...headers, ...Object.entries(sig)],
    body,
    timeoutMs: opts.timeoutMs ?? 30000,
  })
  const d = (res.json ?? {}) as Record<string, unknown>
  const deviceId = String(d.device_id_str ?? '')
  if (!deviceId || deviceId === '0') throw new Error(`device_register 失败：${res.text.slice(0, 200) || '无响应'}`)

  // store-region/ttreq 等设备级 cookie 只在注册响应下发，丢失后 passport 侧会被当成未初始化设备
  const jar = new Jar()
  jar.merge(`passport_csrf_token=${csrf}; passport_csrf_token_default=${csrf}`)
  for (const line of res.setCookie) jar.absorb(line)

  const out = fill({
    ...base,
    ...dev,
    first_install: dev.firstInstall,
    device_id: deviceId,
    iid: String(d.install_id_str ?? ''),
    device_token: String(d.device_token ?? ''),
    device_id_str: deviceId,
    install_id_str: String(d.install_id_str ?? ''),
    new_user: Number(d.new_user ?? 0),
    klink_egdi: String(d.klink_egdi ?? base.klink_egdi),
    dtrait_pk1: String(d.dtrait_pk1 ?? base.dtrait_pk1 ?? ''),
    dtrait_pk2: String(d.dtrait_pk2 ?? base.dtrait_pk2 ?? ''),
    dtrait_pk1_version: String(d.dtrait_pk1_version ?? base.dtrait_pk1_version ?? ''),
    dtrait_pk2_version: String(d.dtrait_pk2_version ?? base.dtrait_pk2_version ?? ''),
    dtrait_token: String(d.dtrait_token ?? base.dtrait_token ?? ''),
    dtrait_version: Number(d.dtrait_version ?? base.dtrait_version ?? 0),
    bind_dtrait: d.bind_dtrait === undefined ? base.bind_dtrait : d.bind_dtrait === true,
    source: 'register',
    cookie: jar.header(),
  })
  if (opts.activate !== false) await activate(out, opts)
  return out
}

/** 激活：app_alert_check（tt_info = base64(ttEncrypt(gzip(query)))）；每次启动都要重新激活 */
export async function activate (ids: Ids, opts: DevOpts = {}): Promise<boolean> {
  const host = (opts.host ?? ACT_HOST).replace(/\/$/, '')
  const dev = regOf(ids)
  const ms = Date.now()
  const ttInfo = ttEncrypt(gzipSync(Buffer.from(qs(actQuery(dev, ms)), 'utf8'))).toString('base64')
  const url = `${host}${ACT_PATH}?aid=${APP.aid}&tt_info=${encodeURIComponent(ttInfo)}`
  const headers = strip(head(ms, undefined, [['x-tt-dt', ids.device_token]])).filter(
    ([k]) => k !== 'content-type' && k !== 'x-ss-dp',
  )
  const sig = soSign(url, undefined, { deviceId: ids.device_id, installId: ids.iid })
  const res = await request({ url, headers: [...headers, ...Object.entries(sig)], timeoutMs: opts.timeoutMs ?? 30000 })
  const msg = String((res.json as { message?: string } | undefined)?.message ?? '')
  return res.status === 200 && (res.headers['bd-tt-error-code'] === '0' || msg === 'success')
}

/** 注册新设备并激活；返回可直接复用的 Ids（由调用方持久化） */
export async function device (base: Ids, opts: DevOpts = {}): Promise<Ids> {
  return reg(fill(base), opts)
}
