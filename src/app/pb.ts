/** App 侧 IM protobuf 信封：按真机 Android 字段组装，schema 复用 web */
import { loadRoot } from '../live/proto.js'
import { clientData, zt } from './guard.js'
import type { Dev, Ids } from './types.js'
import type { Im, ImRes } from './im.js'

export interface PbCall {
  /** 外层 cmd，与 RequestPayload 的 oneof 字段号一致 */
  cmd: number
  /** RequestPayload 内的 oneof 字段名 */
  field: string
  body?: Record<string, unknown>
  token?: string
  /** client-data 的 HMAC 绑定请求路径，必须与 URL path 完全一致 */
  path: string
}

let seq = 0

/** 明文 unread_count 抓包还原的 envelope 默认值；缺省字段会被网关判非法 */
export function pack (dev: Dev, ids: Ids, call: PbCall): Buffer {
  const env = loadRoot().lookupType('im.RequestEnvelope')
  const g = zt(ids)
  const ts = Math.floor(Date.now() / 1000)
  const message = env.create({
    cmd: call.cmd,
    sequenceId: ++seq,
    sdkVersion: '5.0.3.0-rc.11-SNAPSHOT',
    token: call.token ?? '',
    refer: 1,
    inboxType: 0,
    buildNumber: '5030',
    body: { [call.field]: call.body ?? {} },
    deviceId: ids.device_id,
    channel: dev.channel,
    devicePlatform: dev.devicePlatform,
    deviceType: dev.deviceType,
    osVersion: dev.osVersion,
    versionCode: String(dev.versionCode),
    headers: {
      app_name: dev.appName,
      iid: ids.iid,
      version_code: String(dev.versionCode),
      net_mcc_mnc: dev.mccMnc,
      aid: String(dev.aid),
      sim_mcc_mnc: dev.mccMnc,
      'flow-tag': 'new',
      'user-agent': 'okhttp/3.12.13.2',
    },
    configId: 0,
    // 写操作（send 等）只认 PASSPORT_CERT_AUTH(4)+证书四件套；1 会被判 authType must be certAuth
    authType: 4,
    clientCert: g.cert,
    clientData: clientData(ids, call.path, '', ts),
    reePublicKey: g.reeKey,
    iterVersion: '2',
    biz: 'douyin',
    access: 'douyin_main',
  })
  return Buffer.from(env.encode(message).finish())
}

/** 解密后的响应信封转普通对象，int64 统一转字符串避免精度丢失 */
export function unpack (res: ImRes): Record<string, unknown> {
  if (!res.ready) throw new Error(`pb 响应未解密 status=${res.status}`)
  const env = loadRoot().lookupType('im.ResponseEnvelope')
  return env.toObject(env.decode(res.raw), { longs: String, defaults: true }) as Record<string, unknown>
}

/** 组装并下发一次 pb 查询，返回 ResponsePayload 对应 body */
export async function pbQuery (
  im: Im,
  dev: Dev,
  ids: Ids,
  path: string,
  cmd: number,
  field: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const res = await im.call({ path, enc: 'pb', body: pack(dev, ids, { cmd, field, body, token: await im.token(), path }) })
  const env = unpack(res)
  if (Number(env.statusCode ?? 0) !== 0) {
    throw new Error(`${path} 失败 statusCode=${String(env.statusCode)} ${String(env.errorDesc ?? '')}`)
  }
  return (env.body ?? {}) as Record<string, unknown>
}
