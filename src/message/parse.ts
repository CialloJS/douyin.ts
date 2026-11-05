import type { ImageResource, RecvBody, TextMention, VideoResource } from '../types.js'
import { parsers, shareOf } from './body.js'
import { objectValue, stringArray } from './value.js'

/** 类型缺省时按通用资源字段推断的消息类型（其余类型一律 unknown，避免误判） */
const generic = new Set([1, 2, 5, 7, 27, 30])

function imageFromObject (value: Record<string, unknown>): ImageResource | undefined {
  const resource = objectValue(value['resource_url']) ?? value
  const oid = String(resource['oid'] ?? resource['uri'] ?? '')
  const skey = String(resource['skey'] ?? '')
  const urls = (name: string): string[] => stringArray(resource[name] ?? value[name])
  if (!oid && !skey && !['origin_url_list', 'large_url_list', 'medium_url_list', 'thumb_url_list'].some((name) => urls(name).some(Boolean))) return undefined
  return {
    oid,
    skey,
    md5: String(resource['md5'] ?? value['md5'] ?? ''),
    dataSize: Number(resource['data_size'] ?? value['data_size'] ?? 0),
    width: Number(value['cover_width'] ?? resource['width'] ?? 0),
    height: Number(value['cover_height'] ?? resource['height'] ?? 0),
    originUrls: urls('origin_url_list'),
    largeUrls: urls('large_url_list'),
    mediumUrls: urls('medium_url_list'),
    thumbUrls: urls('thumb_url_list'),
  }
}

/** 收侧 @ 提及：仅 infoType=1（@ 人）计入，位置/长度用于从原 text 剥离 */
function mentionsFromValue (value: Record<string, unknown>): TextMention[] | undefined {
  const infos = value['richTextInfos']
  if (!Array.isArray(infos) || infos.length === 0) return undefined
  const mentions = infos
    .map(item => {
      const record = objectValue(item)
      if (!record || Number(record['infoType']) !== 1) return undefined
      const info = objectValue(record['info'])
      return {
        uid: String(info?.['uid'] ?? ''),
        location: Number(record['location'] ?? 0),
        length: Number(record['length'] ?? 0),
      }
    })
    .filter((m): m is TextMention => m !== undefined && m.uid !== '')
  return mentions.length ? mentions : undefined
}

/** 按 location/length 从原文本剥离 @ 片段；从后往前裁避免偏移 */
function stripMentions (text: string, mentions: TextMention[]): string {
  const parts = [...mentions].sort((a, b) => b.location - a.location)
  let rest = text
  for (const m of parts) {
    if (m.location < 0 || m.location + m.length > rest.length) continue
    rest = rest.slice(0, m.location) + rest.slice(m.location + m.length)
  }
  return rest
}

function videoFromObject (value: Record<string, unknown>, text: string): RecvBody {
  const videoValue = objectValue(value['video'])!
  const posterValue = objectValue(value['poster'])
  const poster = posterValue ? imageFromObject(posterValue) : undefined
  const video: VideoResource = {
    tkey: String(videoValue['tkey'] ?? ''),
    skey: String(videoValue['skey'] ?? ''),
    md5: String(videoValue['md5'] ?? ''),
    width: Number(value['width'] ?? 0),
    height: Number(value['height'] ?? 0),
    checkPics: stringArray(value['check_pics']),
    ...(poster ? { poster } : {}),
    ...(value['inline_pic'] ? { inlinePic: String(value['inline_pic']) } : {}),
  }
  return { type: 'video', text, video }
}

/**
 * 解析 wire content 为收侧消息体（RecvBody）：type 判别 + 载荷字段平铺，媒体恒为资产/资源形态。
 * text 为可读展示文本（媒体字段无文案时保持原值，不再内填「[视频]」等占位，
 * 拼接展示交由外部按 type 处理，避免外部再追加时重复）；@ 提及并入 text 的 ats（纯 @ 消息 text 保留原文）。
 */
export function parseBody (content: string, messageType?: number): RecvBody {
  let value: Record<string, unknown>
  try {
    // JSON.parse 前把 16+ 位整数包成字符串：uid/msg_id 等 19 位大整数超出 Number 精度，直接 parse 会丢尾数
    const decoded: unknown = JSON.parse(content.replace(/"(\w+)"\s*:\s*(\d{16,})/g, '"$1":"$2"'))
    if (!objectValue(decoded)) return { type: 'unknown', text: content, raw: content }
    value = decoded as Record<string, unknown>
  } catch {
    return { type: 'text', text: content }
  }
  const aweType = Number(value['aweType'] ?? value['awe_type'] ?? 0)
  const text = String(value['text'] ?? value['content'] ?? value['display_name'] ?? '')
  const typed = messageType == null ? undefined : parsers.get(messageType)?.(value, text)
  if (typed) return typed
  if (messageType == null && aweType === 800) return shareOf(value, text)
  if (messageType != null && !generic.has(messageType)) return { type: 'unknown', text, raw: value }

  const image = imageFromObject(value)
  if (image) return { type: 'image', text, image }

  if (objectValue(value['video'])) return videoFromObject(value, text)

  const emojiUrl = objectValue(value['url'])
  const url = String(emojiUrl?.['uri'] ?? stringArray(emojiUrl?.['url_list'])[0] ?? '')
  if (aweType === 507 || url) return { type: 'emoji', text, emoji: url }
  if (text || 'text' in value) {
    const mentions = mentionsFromValue(value)
    // 有 @ 提及时按原文位置剥离「@xxx 」；纯 @ 消息保留原文（无剥离文本）
    if (!mentions) return { type: 'text', text }
    const stripped = stripMentions(text, mentions)
    const ats = mentions.sort((a, b) => a.location - b.location).map(m => ({ uid: m.uid }))
    return { type: 'text', text: stripped || text, ats }
  }
  return { type: 'unknown', text, raw: value }
}
