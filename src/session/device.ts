/**
 * 桌面设备注册（对齐 douyin-im device-registration）：
 * macOS 硬件画像 → /service/2/desktop/device_register/ 签发数字 device_id/install_id，
 * 服务端认识设备后登录不再强制 MFA。身份只存在进程内，不落盘。
 */
import os from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { gzipSync } from 'node:zlib'
import { createHash } from 'node:crypto'
import { err } from '../error.js'
import { im, mac, reg } from './sign/const.js'
import type { Device, Log } from '../types.js'

const run = promisify(execFile)

interface Hardware {
  release: string
  model: string
  uuid: string
  serial: string
  sku: string
  mac: string
  resolution: string
  timezone: string
  timezoneName: string
  timezoneOffset: number
  language: string
}

/** Desktop 系统设备信息 2.0.1 / passport-util logEncrypt v3（替换+轮转，非 AES） */
const SBOX = Buffer.from('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16', 'hex')
const KEY = Buffer.from('I+D&*76:j27kVH<us9&d').subarray(0, 16).map(b => SBOX[b]!)

function encodeDeviceLog (value: string, timestamp = Date.now()): Buffer {
  const gzip = gzipSync(Buffer.from(value), { level: 6, memLevel: 4 })
  gzip.writeUInt32LE(Math.floor(timestamp / 1000), 4)
  gzip[9] = 3
  const padding = (16 - gzip.length % 16) % 16
  const input = Buffer.concat([gzip, Buffer.alloc(padding, padding)])
  const output = Buffer.alloc(6 + input.length)
  output.set([0x74, 0x63, 3, padding, 0, 3])
  for (let base = 0; base < input.length; base += 16) {
    for (let word = 0; word < 4; word++) {
      for (let byte = 0; byte < 4; byte++) {
        const index = word * 4 + byte
        output[6 + base + index] = SBOX[input[base + word * 4 + (byte + word) % 4]!]! ^ KEY[index]!
      }
    }
  }
  return output
}

/** Desktop 的 Eo(app.getGuid()) 兜底；注册成功后被服务端 DID 替换 */
function guidHash (guid: string): string {
  let hash = 0
  for (let index = 0; index < guid.length; index++) hash = (31 * hash + guid.charCodeAt(index)) >>> 0
  return String(hash)
}

/**
 * 稳定 GUID：同一台机器每次启动一致。
 * 不落盘，用硬件种子派生，注册失败回退的 DID 才不会每次漂移成「新设备」反复触发 MFA。
 */
function stableGuid (hardware: Hardware): string {
  return createHash('sha256').update(`${hardware.uuid}:${hardware.serial}:${hardware.model}`).digest('hex').slice(0, 32)
}

/** 非 darwin 宿主：用本机硬件种子派生稳定的 Apple 口径标识 */
function deriveMac (seed: string): { uuid: string; serial: string; sku: string } {
  const hex = createHash('sha256').update(seed).digest('hex')
  return {
    uuid: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${(8 | (parseInt(hex[16]!, 16) & 3)).toString(16)}${hex.slice(17, 20)}-${hex.slice(20, 32)}`,
    serial: hex.slice(0, 10).toUpperCase(),
    sku: `Mac-${hex.slice(10, 26).toUpperCase()}`,
  }
}

/** darwin 读 ioreg，其他宿主读 WMI 作为种子（与官方桌面客户端同源字段） */
async function readSeed (): Promise<{ uuid: string; serial: string; model?: string; sku?: string }> {
  if (process.platform === 'darwin') {
    const { stdout } = await run('/usr/sbin/ioreg', ['-c', 'IOPlatformExpertDevice', '-d', '2'], { encoding: 'utf8', timeout: 15_000 })
    const pick = (key: string): string =>
      stdout.match(new RegExp(`"${key}"\\s*=\\s*(?:"([^"]*)"|([^\\n]*))`))?.slice(1, 3).find(Boolean)?.trim() ?? ''
    const uuid = pick('IOPlatformUUID').toLowerCase()
    const serial = pick('IOPlatformSerialNumber')
    if (!uuid || !serial) err({ platform: process.platform })
    return { uuid, serial, model: pick('model'), sku: pick('board-id') || pick('target-sub-type') }
  }
  const { stdout } = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    '$s=Get-CimInstance Win32_ComputerSystemProduct; $d=Get-CimInstance Win32_DiskDrive | Where-Object SerialNumber | Select-Object -First 1; @{model=$s.Name;uuid=$s.UUID;serial=$d.SerialNumber} | ConvertTo-Json -Compress'], { encoding: 'utf8', timeout: 15_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true })
  const result = JSON.parse(stdout.trim()) as Record<string, string>
  const uuid = result['uuid']?.trim() ?? ''
  const serial = result['serial']?.trim() ?? ''
  if (!uuid || !serial) err({ platform: process.platform })
  return { uuid, serial }
}

/** 读取本机硬件画像；非 macOS 宿主把本机硬件种子转成 macOS 口径 */
async function readHardware (): Promise<Hardware> {
  let seed: Awaited<ReturnType<typeof readSeed>> | undefined
  try { seed = await readSeed() } catch { /* 硬件不可读时退回稳定的主机种子 */ }
  const base = seed ?? { uuid: `${os.hostname()}:${os.userInfo().username}`, serial: os.arch() }
  const real = seed != null && process.platform === 'darwin'
  const ids = real ? { uuid: base.uuid, serial: base.serial, sku: seed!.sku ?? '' } : deriveMac(`${base.uuid}:${base.serial}`)
  return {
    release: real ? os.release() : mac.release,
    // 非 macOS 宿主的 WMI 型号（如 LENOVO）与 os=MacOS 冲突，统一用 Mac 型号
    model: real ? (seed?.model || mac.model) : mac.model,
    uuid: ids.uuid,
    serial: ids.serial,
    sku: ids.sku,
    mac: Object.values(os.networkInterfaces()).flat().find(e => e?.mac && e.mac !== '00:00:00:00:00:00')?.mac ?? '',
    resolution: mac.screen,
    timezone: new Date().toString().split(' ')[5] ?? '',
    timezoneName: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: -new Date().getTimezoneOffset() * 60,
    language: Intl.DateTimeFormat().resolvedOptions().locale,
  }
}

const platformParams = (hardware: Hardware): Record<string, string> => ({
  aid: '339757',
  channel: reg.channel,
  os: 'MacOS',
  device_platform: 'MacOS',
  version_code: im.version,
  macos_uuid: hardware.uuid,
  macos_serial: hardware.serial,
})

/** 构造 device_register 请求（JSON 整数字段不经 Number，保留 int64） */
function buildRegister (hardware: Hardware): { url: string; body: Buffer } {
  const common = platformParams(hardware)
  const query = new URLSearchParams({ ...common, os_version: hardware.release, device_type: common['device_platform'] })
  const body = {
    header: {
      device_id: 0,
      install_id: 0,
      os: 'MacOS',
      device_platform: 'MacOS',
      sdk_version: '2.0.1',
      aid: 339757,
      mc: hardware.mac,
      channel: reg.channel,
      package: 'com.bytedance.aweme-im-pc.desktop',
      language: hardware.language,
      app_version: im.version,
      os_version: hardware.release,
      device_model: hardware.model,
      time_zone: hardware.timezone,
      tz_name: hardware.timezoneName,
      tz_offset: hardware.timezoneOffset,
      resolution: hardware.resolution,
      app_region: 'cn',
      app_language: 'zh-CN',
      display_name: '抖音聊天',
      macos_uuid: hardware.uuid,
      macos_serial: hardware.serial,
      sku: hardware.sku,
    },
    _gen_time: 0,
    magic_tag: 'ss_app_log',
  }
  return { url: `${im.origin}${reg.path}?${query}`, body: encodeDeviceLog(JSON.stringify(body)) }
}

async function register (hardware: Hardware): Promise<{ deviceId: string; installId: string }> {
  const request = buildRegister(hardware)
  const response = await fetch(request.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'TTNetwork PC' },
    body: new Uint8Array(request.body),
    signal: AbortSignal.timeout(30_000),
  })
  const result = await response.json() as Record<string, unknown>
  if (!response.ok) err(result)
  return {
    deviceId: String(result['device_id_str'] ?? result['device_id']),
    installId: String(result['install_id_str'] ?? result['install_id']),
  }
}

async function activate (hardware: Hardware, device: { deviceId: string; installId: string }): Promise<void> {
  const query = new URLSearchParams({
    ...platformParams(hardware),
    app_name: '抖音聊天',
    device_id: device.deviceId,
    iid: device.installId,
  })
  const response = await fetch(`${im.origin}${reg.alert}?${query}`, { method: 'POST', signal: AbortSignal.timeout(30_000) })
  const result = await response.json() as Record<string, unknown>
  if (!response.ok) err(result)
  if (result['message'] !== 'success') err(result)
}

/**
 * 登录前的设备生命周期（对齐 douyin-im startDeviceLifecycle）：
 * 硬件注册签发 DID；未获确认回退 GUID 哈希（对齐官方兜底）。
 */
export async function createDevice (log?: Log): Promise<Device> {
  const hardware = await readHardware()
  const guid = stableGuid(hardware)
  // GUID 稳定后，注册失败回退的 DID 与上次一致，服务端不会当成新设备重复要求二次验证
  try {
    const registered = await register(hardware)
    await activate(hardware, registered).catch(() => undefined)
    return { ...registered, guid }
  } catch {
    log?.warn(`设备注册未获确认，回退 GUID 哈希 ${guidHash(guid)}`)
    return { deviceId: guidHash(guid), installId: '0', guid }
  }
}
