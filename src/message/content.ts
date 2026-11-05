import type {
  ReplyMessageOptions,
  ReplyPayload,
  ReferenceMeta,
  SendMessageReference,
  TextMention,
} from '../types.js'

/** messageType=1 文本 content（HTTP SDK 可投递） */
export function buildLegacyTextContent (text: string): string {
  return JSON.stringify({ text })
}

/** 创作者 Web 文本消息 content（messageType=7，HTTP 路径 aweType=774） */
export function buildCreatorTextContent (text: string): string {
  return JSON.stringify({ text, aweType: 774 })
}

/** Desktop IM 文本 content；字段和值与 jumpbyte 的成功 HAR 保持一致。 */
export function buildDesktopTextContent (text: string, mentions: TextMention[] = []): string {
  return JSON.stringify({
    aweType: 700,
    type: 0,
    instruction_type: 0,
    item_type_local: -1,
    richTextInfos: mentions.map(mention => ({
      infoType: 1,
      location: mention.location,
      length: mention.length,
      info: {
        uid: mention.uid,
        ...(mention.conId ? { con_id: mention.conId } : {}),
      },
    })),
    text,
    createdAt: 0,
    is_card: false,
    msgHint: '',
  })
}

/**
 * Desktop IM 文本 + @所有人 content：占位「@所有人 」从开头插入（length=5、location=0）。
 * richTextInfos 镜像收侧实测样本（infoType=4 mention_label 标记 + infoType=2 加粗），
 * font_weight 为数字（对齐 HAR 权威样本）——发侧 @all 判定另靠 ext s:mentioned_users="0"。
 */
export function buildAtAllTextContent (text: string): string {
  const label = '@所有人 '
  return JSON.stringify({
    aweType: 700,
    type: 0,
    instruction_type: 0,
    item_type_local: -1,
    richTextInfos: [
      { info: { mention_label: '1' }, infoType: 4, length: label.length, location: 0 },
      { info: { font_weight: 2 }, infoType: 2, length: label.length, location: 0 },
    ],
    text: label + text,
    createdAt: 0,
    is_card: false,
    msgHint: '',
  })
}

/** 文本 + @ 提及合成 content：@ 渲染「@昵称 」占位（无昵称退回 uid），位置记录供 richTextInfos 使用 */
export function textWithAts (
  text: string,
  ats?: Array<{ uid: string; nickname?: string }>,
  conId?: string,
): { content: string; mentions: TextMention[] } {
  const list = ats ?? []
  if (!list.length) return { content: text, mentions: [] }
  let content = text
  const mentions: TextMention[] = []
  for (const at of list) {
    const piece = `@${at.nickname ?? at.uid} `
    mentions.push({ uid: at.uid, conId, location: content.length, length: piece.length })
    content += piece
  }
  return { content: buildDesktopTextContent(content, mentions), mentions }
}

/** 构造引用元数据（refMsgInfo）：任意消息类型均可引用，hint 承载被引用消息类型与摘要 */
export function buildReference (meta: ReferenceMeta): SendMessageReference {
  const reference: SendMessageReference = {
    referencedMessageId: meta.referencedMessageId,
    hint: JSON.stringify({
      refmsg_type: meta.referencedMessageType,
      content: meta.referencedText ?? '',
      refmsg_uid: meta.referencedUid,
      refmsg_sec_uid: meta.referencedSecUid ?? '',
      nickname: meta.nickname ?? '',
      refmsg_content: '',
      version: 0,
      itemId: '',
      scene_type: 0,
    }),
  }
  if (meta.rootMessageId) reference.rootMessageId = meta.rootMessageId
  if (meta.rootMessageConvIndex) reference.rootMessageConvIndex = meta.rootMessageConvIndex
  return reference
}

export function buildReplyPayload (options: ReplyMessageOptions): ReplyPayload {
  const { text, ...meta } = options
  return { content: buildDesktopTextContent(text), reference: buildReference(meta) }
}

/**
 * 将简单 `{"text":"..."}` 或纯文本转为 type=7 内容。
 * HTTP 默认 aweType=774；desktop 发送使用 normalizeDesktopTextMessageContent（aweType=700）。
 */
export function normalizeTextMessageContent (content: string, msgType: number): string {
  if (msgType === 1) {
    try {
      const j = JSON.parse(content) as { text?: string }
      if (j.text != null) return content
    } catch {
      return buildLegacyTextContent(content)
    }
    return content
  }
  if (msgType !== 7) return content
  try {
    const j = JSON.parse(content) as { text?: string; aweType?: number; ai_ext?: string }
    if (j.text != null && j.aweType == null && !('ai_ext' in j)) {
      return buildCreatorTextContent(j.text)
    }
    if (j.aweType != null || j.ai_ext != null) return content
  } catch {
    return buildCreatorTextContent(content)
  }
  return content
}

/** 仅将普通文本转换成 Desktop IM 模板，富媒体保持原样。 */
export function normalizeDesktopTextMessageContent (content: string, msgType: number): string {
  if (msgType !== 7) return normalizeTextMessageContent(content, msgType)
  try {
    // JSON.parse("1") 返回数字而非对象，必须显式校验，否则裸数字/布尔文本会原样发出
    const value = JSON.parse(content) as unknown
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return buildDesktopTextContent(content)
    }
    const record = value as Record<string, unknown>
    const keys = Object.keys(record)
    const isPlainText =
      typeof record['text'] === 'string' &&
      keys.every((key) => ['text', 'aweType', 'type', 'richTextInfos'].includes(key)) &&
      (!Array.isArray(record['richTextInfos']) || record['richTextInfos'].length === 0)
    return isPlainText ? buildDesktopTextContent(record['text'] as string) : content
  } catch {
    return buildDesktopTextContent(content)
  }
}
