import { createHash } from 'node:crypto'
import { err } from '../error.js'
import { site } from '../session/codes.js'
import { decodeResponseRaw, encodeRequest } from './codec.js'
import { buildCmd411Frame } from './frame.js'
import { PC_UA, desk, fingerprintParams, native } from './profile.js'
import { AndroidFrontierWs } from './ws.js'
import type { Cmd411FrameOptions } from './frame.js'
import type { Http } from '../session/http.js'
import type { Log } from '../types.js'
import type { Channel } from './profile.js'

export { PC_UA, fingerprintParams, buildCmd411Frame }
export type { Cmd411FrameOptions }

/** HTTP protobuf 通道：Desktop Cookie 通道（发送/收件箱查询/动作/撤回/陌生人消息） */
export class ProtoTransport {
  constructor (
    private readonly http: Http,
    private readonly log: Log,
  ) {}

  /** Desktop Cookie 通道（设备身份在 URL query，envelope headers 为空） */
  sendCookieProto (
    cmd: number,
    inboxType: number,
    endpoint: string,
    body: Record<string, unknown>,
    deviceId: string,
  ): Promise<Record<string, unknown>> {
    return this.send(desk, cmd, inboxType, endpoint, body, deviceId)
  }

  /** 原生通道（imapi.douyin.com：无 URL query、无 x-ss-stub，设备身份在 envelope f15 headers map） */
  sendNativeProto (
    cmd: number,
    inboxType: number,
    endpoint: string,
    body: Record<string, unknown>,
    deviceId: string,
  ): Promise<Record<string, unknown>> {
    return this.send(native, cmd, inboxType, endpoint, body, deviceId)
  }

  private async send (
    channel: Channel,
    cmd: number,
    inboxType: number,
    endpoint: string,
    body: Record<string, unknown>,
    deviceId: string,
  ): Promise<Record<string, unknown>> {
    const payload = Buffer.from(encodeRequest({
      token: '',
      cmd,
      inboxType,
      body,
      authType: 1,
      deviceId,
      sdkVersion: channel.sdkVersion,
      buildNumber: channel.buildNumber,
      versionCode: channel.versionCode,
      devicePlatform: channel.devicePlatform,
      biz: channel.biz,
      access: channel.access,
      headers: channel.headers(deviceId),
    }))
    const headers: Record<string, string> = {
      Accept: channel.accept,
      'Content-Type': 'application/x-protobuf',
      'User-Agent': PC_UA,
      Referer: site.im,
    }
    // Native Cronet SetMD5Header：请求体 MD5 hex（非签名，但缺失会被网关拒绝）
    if (channel.stub) headers['x-ss-stub'] = createHash('md5').update(payload).digest('hex')
    const res = await this.http.bytes(channel.url(endpoint, deviceId), {
      method: 'POST',
      headers,
      body: payload,
    })
    if (!res.ok) return err(res.data)
    return this.decode(cmd, endpoint, res.data)
  }

  /** 两条通道共用的响应解码与失败诊断 */
  private decode (cmd: number, endpoint: string, data: Uint8Array): Record<string, unknown> {
    const decoded = decodeResponseRaw(data)
    const statusCode = Number(decoded['statusCode'] ?? 0)
    if (statusCode !== 0) {
      this.log.warn(`cmd=${cmd} ${endpoint} 失败: statusCode=${statusCode} errorDesc=${String(decoded['errorDesc'] ?? '')}`)
    }
    return decoded
  }
}

export interface Cmd411SendOptions extends Cmd411FrameOptions {
  /** 浏览器 Cookie 串（WS 握手鉴权） */
  cookies: string
}

/** 一次性连接发送 cmd=411 输入状态帧（无确认回执，发完即关）；true=已发出 */
export async function sendCmd411 (options: Cmd411SendOptions): Promise<boolean> {
  const frame = buildCmd411Frame(options)
  const ws = new AndroidFrontierWs({ userId: options.userId, cookies: options.cookies })
  const ok = await ws.sendFireOnce(frame)
  ws.close()
  return ok
}
