import { err } from '../error.js'
import { isInput, resolveMedia, fileNameOf } from '../media/source.js'
import { probeVideo, extractVideoPoster } from '../media/video.js'
import { sendBody, sendTyping, startVoiceCall } from '../message/send.js'
import { recall, modifyReaction, markConversationRead } from '../message/action.js'
import { emojiTextOf } from '../message/emoji.js'
import { toAddress, referenceOf } from './address.js'
import type { Bot } from './bot.js'
import type {
  BotMessage, MarkReadItem, MsgBody, RecallItem, RecallResult, ReplyOptions,
  SendBodyOptions, SendMessageResponse, VoiceCallResult,
} from '../types.js'

type StatusResult = { statusCode: number; statusMsg: string }

export class Msg {
  constructor (private readonly bot: Bot) {}

  /** 统一发送：type 判别一条消息；媒体输入源自动上传，收侧消息对象可直接回传当引用 */
  async send (chatId: string, body: MsgBody, opts?: SendBodyOptions & { reply?: BotMessage }): Promise<SendMessageResponse> {
    const reference = opts?.reply ? referenceOf(opts.reply) : opts?.reference
    return sendBody(this.bot.ctx().send, toAddress(chatId), await this.prepare(body), {
      ...(opts?.clientMessageId ? { clientMessageId: opts.clientMessageId } : {}),
      ...(reference ? { reference } : {}),
    })
  }

  /** 编辑不支持：HTTP 复用原 cmid 会被服务端幂等去重，官方编辑走 App 专属通道 */
  async edit (chatId: string, clientMessageId: string, body: MsgBody): Promise<SendMessageResponse> {
    return sendBody(this.bot.ctx().send, toAddress(chatId), await this.prepare(body), { clientMessageId })
  }

  /** 媒体输入源归一化：简写源先上传为资产，预上传 asset 原样透传 */
  private async prepare (body: MsgBody): Promise<MsgBody> {
    const uploader = this.bot.ctx().uploader
    if (body.type === 'text' && body.ats?.some(at => !at.nickname)) {
      // @ 昵称自动补：缺 nickname 的项按 uid 查缓存/好友列表，占位渲染真艾特
      const ats = await Promise.all(body.ats.map(async at => ({
        ...at,
        nickname: at.nickname ?? await this.bot.nickOf(at.uid),
      })))
      return { ...body, ats }
    }
    if (body.type === 'image') {
      if (!isInput(body.image)) return body
      return { ...body, image: await uploader.uploadImage(await resolveMedia(body.image)) }
    }
    if (body.type === 'video') {
      const video = body.video
      if (!('source' in video)) return body
      const bytes = await resolveMedia(video.source)
      const dims = await probeVideo(bytes)
      let width = video.width ?? dims.width
      let height = video.height ?? dims.height
      let poster = video.poster
      if (poster !== undefined) {
        poster = isInput(poster) ? await uploader.uploadImage(await resolveMedia(poster)) : poster
      } else {
        // 无封面：本地解出首帧当封面，顺带以像素尺寸兜底宽高
        const shot = await extractVideoPoster(bytes)
        poster = await uploader.uploadImage(shot.jpeg)
        width ||= shot.width
        height ||= shot.height
      }
      return {
        ...body,
        video: {
          asset: await uploader.uploadVideo(bytes),
          poster,
          width: width > 0 ? width : undefined,
          height: height > 0 ? height : undefined,
        },
      }
    }
    if (body.type === 'file') {
      const file = body.file
      if (!('source' in file)) return body
      return { ...body, file: { asset: await uploader.uploadFile(await resolveMedia(file.source), file.name ?? fileNameOf(file.source)) } }
    }
    return body
  }

  /** 上报输入状态（true 正在输入 / false 停止） */
  sendTyping (chatId: string, typing: boolean): Promise<boolean> {
    return sendTyping(this.bot.ctx().send, toAddress(chatId), typing)
  }

  /** 发起语音通话（服务端无 VOIP 通道，返回 statusCode=-1） */
  call (chatId: string, calleeUid: string): Promise<VoiceCallResult> {
    return startVoiceCall(this.bot.ctx().send, toAddress(chatId), calleeUid)
  }

  /** 引用回复：任意消息类型均可引，body 可为文本或任意消息体；文本为空不发送 */
  async reply (chatId: string, msg: BotMessage, body: string | MsgBody, opts?: Pick<ReplyOptions, 'atAll' | 'ats'>): Promise<SendMessageResponse> {
    const content: MsgBody = typeof body === 'string'
      ? {
          type: 'text',
          text: body,
          ...(opts?.atAll ? { atAll: true } : {}),
          ...(opts?.ats?.length ? { ats: opts.ats } : {}),
        }
      : body
    if (content.type === 'text' && !content.text.trim()) return err({ text: content.text })
    return this.send(chatId, content, { reply: msg })
  }

  recall (chatId: string, serverMessageId: string): Promise<RecallResult> {
    const item: RecallItem = { ...toAddress(chatId), serverMessageId }
    return recall(this.bot.ctx().inbox, item)
  }

  /** 表情回应：emoji 传抖音键值（如 '[爱心]'）或小表情 id（如 weixiao），isSet false 取消 */
  async react (chatId: string, serverMessageId: string, emoji: string, isSet = true): Promise<StatusResult> {
    const skey = (await emojiTextOf(this.bot.ctx().http, emoji)) ?? emoji
    return modifyReaction(this.bot.ctx().inbox, {
      ...toAddress(chatId),
      serverMessageId,
      emoji: skey,
      operatorUid: this.bot.id,
      enabled: isSet,
    })
  }

  /** 标记已读；msg 缺省读到底 */
  read (chatId: string, msg?: BotMessage): Promise<StatusResult> {
    const item: MarkReadItem = {
      ...toAddress(chatId),
      readMessageIndex: msg?.createTime,
      readMessageIndexV2: msg?.indexInConversationV2,
      serverMessageId: msg?.serverMessageId,
    }
    return markConversationRead(this.bot.ctx().inbox, item)
  }
}
