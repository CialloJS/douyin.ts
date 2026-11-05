/** 门面共享上下文：HTTP、设备、传输与收发域参数只组装一次，各能力模块按需取用 */
import { ProtoTransport } from '../live/transport.js'
import { Uploader } from '../media/upload.js'
import { createLog } from '../session/log.js'
import type { Http } from '../session/http.js'
import type { InboxContext, ImOptions, Log } from '../types.js'
import type { SendContext } from '../message/send.js'

export interface Ctx {
  http: Http
  userId: string
  deviceId: string
  cookies: string
  log: Log
  transport: ProtoTransport
  uploader: Uploader
  inbox: InboxContext
  send: SendContext
}

export function createCtx (opts: ImOptions): Ctx {
  const userId = opts.userId
  const deviceId = opts.deviceId ?? opts.http.deviceId
  const log = opts.log ?? createLog({ tag: 'im' })
  const transport = new ProtoTransport(opts.http, log)
  return {
    http: opts.http,
    userId,
    deviceId,
    cookies: opts.cookies,
    log,
    transport,
    uploader: new Uploader(opts.http, userId),
    inbox: { transport, http: opts.http, deviceId, platformUid: userId },
    send: { transport, deviceId, log, http: opts.http, userId, cookies: opts.cookies },
  }
}
