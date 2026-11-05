import { LONG } from '../session/pb.js'
import { randomUUID } from 'node:crypto'
import { normalizeDesktopTextMessageContent } from './content.js'
import type { ProtoTransport } from '../live/transport.js'
import type { Http } from '../session/http.js'
import type { Log, SendMessageItem, SendMessageReference, SendMessageResponse } from '../types.js'

/** 发送上下文：统一 HTTP cookie 通道（native ImOption profile）+ WS cmd411 输入状态通道 */
export interface SendContext {
  transport: ProtoTransport
  deviceId: string
  log: Log
  /** 直连 HTTP 客户端（云端接口：合并转发凭证/视频地址等） */
  http: Http
  /** 账号 uid（cmd411 帧 envelope device_id） */
  userId: string
  /** 浏览器 Cookie 串（cmd411 WS 握手鉴权） */
  cookies: string
}

function encodeReference (reference: SendMessageReference): Record<string, unknown> {
  return {
    referencedMessageId: LONG.fromString(reference.referencedMessageId),
    hint: reference.hint,
    ...(reference.rootMessageId ? { rootMessageId: LONG.fromString(reference.rootMessageId) } : {}),
    ...(reference.rootMessageConvIndex
      ? { rootMessageConvIndex: LONG.fromString(reference.rootMessageConvIndex) }
      : {}),
  }
}

/** cmd=100 /v1/message/send — 统一发送（文本/媒体/引用/编辑/盖楼全走 HTTP）。 */
export async function send (
  ctx: SendContext,
  options: SendMessageItem,
): Promise<SendMessageResponse> {
  const clientMessageId = options.clientMessageId ?? randomUUID()
  const timestamp = Date.now()
  const decoded = await ctx.transport.sendCookieProto(
    100,
    options.inboxType ?? 0,
    '/v1/message/send',
    {
      sendMessage: {
        conversationId: options.conversationId,
        conversationType: options.conversationType ?? 1,
        conversationShortId: LONG.fromString(options.conversationShortId || '0'),
        content: normalizeDesktopTextMessageContent(options.content, options.messageType ?? 7),
        messageType: options.messageType ?? 7,
        clientMessageId,
        ext: {
          // @所有人 值填 "0"（HAR 权威样本：web 客户端 @all 时 ext 含 s:mentioned_users="0"），普通消息留空
          's:mentioned_users': options.atAll ? '0' : '',
          's:client_message_id': clientMessageId,
          's:stime': `${timestamp}.${String(timestamp % 10_000).padStart(4, '0')}`,
        },
        ...(options.reference ? { refMsgInfo: encodeReference(options.reference) } : {}),
        // @所有人 必须显式写 f9 mentioned_users=[0]（HAR 权威样本：真 @all 请求 SendMessageRequest.f9=0；
        // 0 是「全体」约定，缺省则服务端不识别为真 @all，ext 的 s:mentioned_users 只是透传标记）
        ...(options.atAll
          ? { mentionedUsers: [LONG.fromString('0')] }
          : options.mentionedUsers?.length
            ? { mentionedUsers: options.mentionedUsers.map(uid => LONG.fromString(uid)) }
            : {}),
      },
    },
    ctx.deviceId,
  )
  const result = parseSendResponse(decoded, clientMessageId)
  if (result.checkCode === 10502) {
    // 文件/媒体消息常见：已提交、审核放行（raw_check_code=1），异步审核后对方可见
    ctx.log.info('消息已提交，审核中（10502），对方可能延迟可见')
  } else if (result.statusCode !== 0) {
    ctx.log.warn(
      `发送被拒: send={id:${options.conversationId} type:${options.conversationType ?? 1} ` +
      `short:${options.conversationShortId}} ` +
      `statusCode=${result.statusCode} check=${result.checkCode ?? '-'} detail=${result.statusMsg}`,
    )
  }
  return result
}

/** body.sendMessageBody 解析：serverMessageId/status/checkCode/checkMessage */
function parseSendResponse (decoded: Record<string, unknown>, clientMessageId: string): SendMessageResponse {
  const statusCode = Number(decoded['statusCode'] ?? 0)
  const body = decoded['body'] as Record<string, unknown> | undefined
  const sendBody = body?.['sendMessage'] as {
    status?: number
    serverMessageId?: string | number
    clientMessageId?: string
    checkCode?: string | number
    checkMessage?: string
  } | undefined

  const rawCheckCode = Number(sendBody?.checkCode ?? 0)
  let checkCode = rawCheckCode > 0 ? rawCheckCode : undefined
  let checkTips = ''
  if (sendBody?.checkMessage) {
    try {
      const check = JSON.parse(sendBody.checkMessage) as { status_code?: number; tips?: string }
      if (Number(check.status_code) > 0) checkCode = Number(check.status_code)
      checkTips = String(check.tips ?? '')
    } catch { /* 非 JSON 保持原值 */ }
  }

  const sendStatus = Number(sendBody?.status ?? 0)
  const serverMessageId = sendBody?.serverMessageId != null ? String(sendBody.serverMessageId) : undefined
  const envelopeMsg = String(decoded['errorDesc'] ?? '')
  const delivered = statusCode === 0 && sendStatus === 0 && !!serverMessageId && serverMessageId !== '0'
  if (!delivered) {
    return {
      statusCode: statusCode || sendStatus || -1,
      statusMsg: checkTips || envelopeMsg || 'send rejected',
      clientMessageId,
      ...(checkCode !== undefined ? { checkCode } : {}),
    }
  }
  return {
    statusCode: 0,
    statusMsg: envelopeMsg,
    serverMessageId,
    clientMessageId: sendBody?.clientMessageId ?? clientMessageId,
    ...(checkCode !== undefined ? { checkCode } : {}),
  }
}
