import { err } from '../error.js'
import { send } from './core.js'
import type { SendContext } from './core.js'
import type { ForwardNode, SendForwardOptions, SendMessageResponse } from '../types.js'

/** 节点文本摘要：文字原样，媒体占位（list_content.text） */
function nodeSummaryText (message: Array<{ type: string; text?: string }>): string {
  return message.map((el) => {
    if (el.type === 'text') return el.text ?? ''
    if (el.type === 'image') return '[图片]'
    if (el.type === 'video') return '[视频]'
    if (el.type === 'record') return '[语音]'
    return `[${el.type}]`
  }).join('')
}

/** 节点消息类型：文本 7/700，图片 27/2702，其余按文本处理 */
function nodeMessageType (message: Array<{ type: string }>): { msgType: number; aweType: number } {
  const first = message[0]?.type
  if (first === 'image') return { msgType: 27, aweType: 2702 }
  return { msgType: 7, aweType: 700 }
}

/** JSON 序列化：BigInt 输出为裸数字（uid/msg_id 等 19 位大整数超出 Number 精度，服务端按数字解析） */
function rawJson (value: unknown): string {
  return JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? `\u0000${v}\u0000` : v))
    .replace(/"\u0000(-?\d+)\u0000"/g, '$1')
}

/**
 * 合并转发（messageType=136）：list_content 为节点预览摘要，msg_ids 引用会话真实消息
 * （msg_id 须为原消息 serverMessageId）。协议限制：新版 App 点开按 upload_key 从云端拉取
 * 记录渲染，而云端注册接口 merge_msg_card/prepare 仅部署在 App 域（需 App 签名与登录态，
 * web/桌面域 status 4），故 SDK 只能发摘要卡片，接收端点开无内容。
 */
export async function sendMergeForward (
  ctx: SendContext,
  options: SendForwardOptions,
): Promise<SendMessageResponse> {
  if (!options.nodes.length) return err({ nodes: options.nodes })
  const timestamp = Date.now()
  const listContent = options.nodes.map(node => ({
    msgid: BigInt(node.msgId),
    nick_name: node.nickname,
    text: node.text,
  }))
  const msgIds = options.nodes.map(node => ({
    msg_id: BigInt(node.msgId),
    msg_type: node.msgType,
    awe_type: node.aweType,
    show_flag: true,
    uid: BigInt(node.uid),
    ...(node.secUid ? { sec_uid: node.secUid } : {}),
    create_time: node.createTime ?? timestamp,
    ref_msg_invisible: 0,
  }))
  const content = rawJson({
    list_content: listContent,
    msg_ids: msgIds,
    origin_conv_id: BigInt(options.conversationShortId),
    title: `${options.nodes[0]?.nickname ?? ''} 的聊天记录`,
  })
  return send(ctx, { ...options, content, messageType: 136 })
}

/** 节点数组 → ForwardNode（客户端生成 19 位数字 msg_id） */
export function buildForwardNodes (
  nodes: Array<{ userId: string; nickname: string; message: Array<{ type: string; text?: string }> }>,
  selfUid: string,
  selfSecUid: string | undefined,
): ForwardNode[] {
  const timestamp = Date.now()
  return nodes.map((node, index) => {
    const { msgType, aweType } = nodeMessageType(node.message)
    return {
      uid: node.userId || selfUid,
      nickname: node.nickname || '',
      text: nodeSummaryText(node.message),
      msgType,
      aweType,
      msgId: String(BigInt(timestamp) * 1000n + BigInt(index)),
      ...(node.userId === selfUid && selfSecUid ? { secUid: selfSecUid } : {}),
      createTime: timestamp,
    }
  })
}
