/** App 发送内容构造：统一消息体转成 IM 帧的 messageType 与 content；媒体只接受已上传资产 */
import { err } from '../error.js'
import { isInput } from '../media/source.js'
import { buildAtAllTextContent, textWithAts } from '../message/content.js'
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
} from '../message/rich.js'
import type { MsgBody } from '../types.js'

export interface Wire {
  messageType: number
  content: string
  atAll?: boolean
  mentionedUsers?: string[]
}

/**
 * 把统一消息体转成 IM 帧字段。
 * App 网关不代传媒体，输入源（URL/本地/字节）需先在 cookie 通道上传，这里拒绝以免发出坏帧；
 * 表情仅支持完整资源直链，小表情 id 与 im-resource id 的解析依赖 web 接口，App 通道不可用。
 */
export function wire (body: MsgBody, uid: string, conId?: string): Wire {
  switch (body.type) {
    case 'text': {
      if (body.atAll) return { messageType: 7, content: buildAtAllTextContent(body.text), atAll: true }
      const { content, mentions } = textWithAts(body.text, body.ats, conId)
      return {
        messageType: 7,
        content,
        ...(mentions.length ? { mentionedUsers: [...new Set(mentions.map(m => m.uid))] } : {}),
      }
    }
    case 'image': {
      if (isInput(body.image)) return err({ image: body.image })
      return { messageType: 27, content: buildImageContent(body.image) }
    }
    case 'video': {
      const video = body.video
      if ('source' in video) return err({ video })
      if (!('asset' in video)) return { messageType: 30, content: buildVideoContent(video) }
      const { asset, poster, width, height } = video
      return {
        messageType: 30,
        content: buildVideoContent({
          ...asset,
          ...(poster ? { poster } : {}),
          ...(width !== undefined ? { width } : {}),
          ...(height !== undefined ? { height } : {}),
        }),
      }
    }
    case 'file': {
      const file = body.file
      if ('source' in file) return err({ file })
      // App 端文件消息用 150（aweType=15001），6 会被判不支持该类型
      return { messageType: 150, content: buildFileContent('asset' in file ? file.asset : file) }
    }
    case 'share':
      return { messageType: 8, content: buildShareContent(body.share, uid) }
    case 'userCard':
      return { messageType: 25, content: buildUserCardContent(body.user) }
    case 'emoji': {
      if (!/^https?:\/\//.test(body.emoji)) return err({ emoji: body.emoji })
      return { messageType: 5, content: buildEmojiContent(body.emoji, body.text) }
    }
    case 'card':
      return { messageType: 110, content: buildCardContent(body.card, body.text ?? body.card.title ?? '') }
    case 'location':
      return { messageType: 502, content: buildLocationContent(body.location) }
    case 'groupCard':
      return { messageType: 58, content: buildGroupCardContent(body.groupCard, uid) }
    // 合并转发由 send 编排先调 App 域 prepare，不经过这里
    default:
      return err({ type: body.type })
  }
}
