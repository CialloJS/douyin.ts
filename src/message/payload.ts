import { err } from '../error.js'
import { isInput } from '../media/source.js'
import { buildAtAllTextContent, textWithAts } from './content.js'
import {
  buildCardContent,
  buildEmojiContent,
  buildFileContent,
  buildGroupCardContent,
  buildImageContent,
  buildLocationContent,
  buildShareContent,
  buildUserCardContent,
  buildVideoContent,
} from './rich.js'
import { send } from './core.js'
import { sendMergeForward } from './forward.js'
import { emojiTextOf } from './emoji.js'
import { stickerUrlOf } from './resource.js'
import type { SendContext } from './core.js'
import type {
  ConversationAddress,
  MsgBody,
  SendBodyOptions,
  SendFileOptions,
  SendMediaOptions,
  SendMessageResponse,
  SendShareOptions,
  SendUserCardOptions,
  SendVideoOptions,
} from '../types.js'

type BodyOf<K extends MsgBody['type']> = Extract<MsgBody, { type: K }>

type Handler = (
  ctx: SendContext,
  address: ConversationAddress,
  body: MsgBody,
  extra: SendBodyOptions,
) => Promise<SendMessageResponse>

const onText: Handler = (ctx, address, body, extra) => {
  const item = body as BodyOf<'text'>
  if (item.atAll) {
    // @所有人：content 前置「@所有人 」占位（infoType=4 mention_label 元数据），
    // ext 写 s:mentioned_users="0"（HAR 权威样本）；与 ats 同给时 atAll 优先。
    return send(ctx, {
      ...address,
      content: buildAtAllTextContent(item.text),
      messageType: 7,
      atAll: true,
      ...extra,
    })
  }
  const { content, mentions } = textWithAts(item.text, item.ats, address.conversationId)
  return send(ctx, {
    ...address,
    content,
    messageType: 7,
    ...(mentions.length ? { mentionedUsers: [...new Set(mentions.map(m => m.uid))] } : {}),
    ...extra,
  })
}

const onImage: Handler = (ctx, address, body, extra) => {
  const item = body as BodyOf<'image'>
  if (isInput(item.image)) return err({ image: item.image })
  return sendImage(ctx, { ...address, image: item.image, ...extra })
}

const onVideo: Handler = (ctx, address, body, extra) => {
  const video = (body as BodyOf<'video'>).video
  if ('source' in video) return err({ video })
  if (!('asset' in video)) return sendVideo(ctx, { ...address, video, ...extra })
  const { asset, poster, width, height } = video
  return sendVideo(ctx, {
    ...address,
    video: {
      tkey: asset.tkey,
      skey: asset.skey,
      md5: asset.md5,
      ...(poster ? { poster } : {}),
      ...(width !== undefined ? { width } : {}),
      ...(height !== undefined ? { height } : {}),
    },
    ...extra,
  })
}

const onFile: Handler = (ctx, address, body, extra) => {
  const file = (body as BodyOf<'file'>).file
  if ('source' in file) return err({ file })
  return sendFile(ctx, { ...address, file: 'asset' in file ? file.asset : file, ...extra })
}

const onShare: Handler = (ctx, address, body, extra) =>
  sendShare(ctx, { ...address, item: (body as BodyOf<'share'>).share, ...extra })

const onUserCard: Handler = (ctx, address, body, extra) =>
  sendUserCard(ctx, { ...address, user: (body as BodyOf<'userCard'>).user, ...extra })

const onForward: Handler = (ctx, address, body, extra) =>
  sendMergeForward(ctx, {
    ...address,
    nodes: (body as BodyOf<'forward'>).nodes,
    selfUid: ctx.userId,
    ...extra,
  })

const onEmoji: Handler = async (ctx, address, body, extra) => {
  const item = body as BodyOf<'emoji'>
  // 小表情 id（如 weixiao）按官方形态以键值文本发送（tos-cn 域发 lite_emoji 会被 s:visible 仅自身可见）
  const text = await emojiTextOf(ctx.http, item.emoji)
  if (text) return send(ctx, { ...address, content: text, messageType: 7, ...extra })
  // 表情消息（lite_emoji / messageType=5，HAR 权威样本：url 为完整 CDN 直链，display_name 为表情名）
  // emoji 传完整 URL 或 im-resource 资源 id（id 经 trending 缓存解析为签名直链）
  return send(ctx, {
    ...address,
    content: buildEmojiContent(await stickerUrlOf(ctx.http, item.emoji), item.text),
    messageType: 5,
    ...extra,
  })
}

const onCard: Handler = (ctx, address, body, extra) => {
  const item = body as BodyOf<'card'>
  // 互动卡原样回传：patch 复用收侧载荷（含官方签名），description/push_detail 取展示文本
  return send(ctx, {
    ...address,
    content: buildCardContent(item.card, item.text ?? item.card.title ?? ''),
    messageType: 110,
    ...extra,
  })
}

const onLocation: Handler = (ctx, address, body, extra) =>
  send(ctx, {
    ...address,
    content: buildLocationContent((body as BodyOf<'location'>).location),
    messageType: 502,
    ...extra,
  })

const onGroupCard: Handler = (ctx, address, body, extra) => {
  const item = body as BodyOf<'groupCard'>
  // 群聊邀请卡原样回传：from_uid 缺省以发送者身份填充，title/desc 自动构造
  return send(ctx, {
    ...address,
    content: buildGroupCardContent(item.groupCard, ctx.userId),
    messageType: 58,
    ...extra,
  })
}

/** 消息类型 → 发送策略：text/媒体/卡片/转发各一条消息，新增类型只注册不分支 */
const handlers = new Map<MsgBody['type'], Handler>([
  ['text', onText],
  ['image', onImage],
  ['video', onVideo],
  ['file', onFile],
  ['share', onShare],
  ['userCard', onUserCard],
  ['forward', onForward],
  ['emoji', onEmoji],
  ['card', onCard],
  ['location', onLocation],
  ['groupCard', onGroupCard],
])

/**
 * 统一发送：type 判别各成一条消息（text 合 messageType=7、image 27 / video 30 / file 6 /
 * share 8 / user 25 / forward 136）；媒体字段须为已上传资产，输入源先经 bot.msg.send 自动上传。
 */
export async function sendBody (
  ctx: SendContext,
  address: ConversationAddress,
  body: MsgBody,
  opts?: SendBodyOptions,
): Promise<SendMessageResponse> {
  const handler = handlers.get(body.type)
  // 附加选项统一透传：clientMessageId（幂等去重）与 reference（引用回复，任意消息类型均可引）
  if (!handler) {
    ctx.log.warn(`不支持发送的消息类型 ${body.type}，已跳过`)
    return err({ type: body.type })
  }
  return handler(ctx, address, body, { clientMessageId: opts?.clientMessageId, reference: opts?.reference })
}

/** 发送图片（gif → aweType 2703，其余 2702；messageType=27） */
export async function sendImage (ctx: SendContext, options: SendMediaOptions): Promise<SendMessageResponse> {
  return send(ctx, { ...options, content: buildImageContent(options.image), messageType: 27 })
}

/** 发送视频（messageType=30，content 无 aweType） */
export async function sendVideo (ctx: SendContext, options: SendVideoOptions): Promise<SendMessageResponse> {
  return send(ctx, { ...options, content: buildVideoContent(options.video), messageType: 30 })
}

/** 发送文件（messageType=6、aweType=15001；9 会被客户端判「请升级最新版」，6 可发出但部分客户端渲染异常） */
export async function sendFile (ctx: SendContext, options: SendFileOptions): Promise<SendMessageResponse> {
  return send(ctx, { ...options, content: buildFileContent(options.file), messageType: 6 })
}

/** 发送作品分享卡片（messageType=8 / aweType=800） */
export async function sendShare (ctx: SendContext, options: SendShareOptions): Promise<SendMessageResponse> {
  return send(ctx, { ...options, content: buildShareContent(options.item, ctx.userId), messageType: 8 })
}

/** 发送用户名片卡片（messageType=25 / aweType=0） */
export async function sendUserCard (ctx: SendContext, options: SendUserCardOptions): Promise<SendMessageResponse> {
  return send(ctx, { ...options, content: buildUserCardContent(options.user), messageType: 25 })
}
