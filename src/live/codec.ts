import { err } from '../error.js'
import { cmd } from '../session/codes.js'
import { loadRoot } from './proto.js'
import type { EncodeRequestOptions } from './types.js'

const SDK_VERSION = cmd.version
const BUILD_NUMBER = cmd.build

let sequenceCounter = 0

export function encodeRequest (opts: EncodeRequestOptions): Uint8Array {
  const root = loadRoot()
  const RequestEnvelope = root.lookupType('im.RequestEnvelope')

  sequenceCounter += 1
  const envelope: Record<string, unknown> = {
    cmd: opts.cmd,
    sequenceId: opts.sequenceId ?? sequenceCounter,
    sdkVersion: opts.sdkVersion ?? SDK_VERSION,
    token: opts.token,
    refer: opts.refer ?? 3,
    inboxType: opts.inboxType ?? 1,
    buildNumber: opts.buildNumber ?? BUILD_NUMBER,
    deviceId: opts.deviceId ?? '',
    devicePlatform: opts.devicePlatform ?? 'douyin_pc',
    versionCode: opts.versionCode ?? '',
    headers: opts.headers ?? {},
    authType: opts.authType ?? 3,
    biz: opts.biz ?? 'douyin_creator',
    access: opts.access ?? 'im_api',
  }

  if (opts.body) {
    envelope['body'] = opts.body
  }

  const errMsg = RequestEnvelope.verify(envelope)
  if (errMsg) err({ reason: errMsg })

  const message = RequestEnvelope.create(envelope)
  return RequestEnvelope.encode(message).finish()
}

export function decodeResponseRaw (buffer: Uint8Array): Record<string, unknown> {
  const root = loadRoot()
  const ResponseEnvelope = root.lookupType('im.ResponseEnvelope')
  const decoded = ResponseEnvelope.decode(buffer)
  return ResponseEnvelope.toObject(decoded, {
    longs: String,
    enums: String,
    defaults: true,
  }) as Record<string, unknown>
}
