import { decodeWire, decodeWireTree, type WireField } from '../live/wire.js'
import { cmd } from '../session/codes.js'
import { fieldString, collectKeyValues } from '../notice/notice.js'
import { parseContent, str } from './json.js'
import type { PushMessage } from '../types.js'

/** content 恒为空、信息全在 ext 的命令帧类型（50005 会话删除/群解散，实证帧 content 为空） */
const bodyless = new Set(cmd.bodyless)

interface MessageContext {
  cmd?: number
  inboxType?: number
  conversationId?: string
  senderUid?: string
  senderSecUid?: string
  conversationShortId?: string
  serverMessageId?: string
  /** 盖楼层 id（serverMessageId:clientMessageId:convShortId） */
  threadId?: string
  /** 盖楼短 id */
  threadShortId?: string
  /** 盖楼根消息（messageType=50002、正文为空） */
  isThreadRoot?: boolean
  /** 消息编辑次数（ext s:edit_count） */
  editCount?: number
  /** 编辑元数据（ext s:edit_info） */
  editInfo?: { contentIsEdited: boolean; editorUid: string; editTime: string }
  /** 编辑前原始消息类型（ext s:org_msg_type） */
  orgMsgType?: number
  indexInConversation?: string
  indexInConversationV2?: string
  createTime?: string
  reference?: NonNullable<PushMessage['reference']>
}

/**
 * 无 schema 提取嵌套引用信息（对齐实际帧形态）：
 * field 1 = referencedMessageId（int64 → varint），field 2 = hint JSON（含 refmsg_type/refmsg_uid 等键），
 * field 3 = refmsg_type（公告/系统消息等无本地上下文），field 8/9 = 被引消息索引。
 * 引用的是无上下文消息（如群公告 refmsg_type=1004）时只透出 replyid，不编造 rootMessageId。
 */
function extractReference (fields: WireField[]): NonNullable<PushMessage['reference']> | undefined {
  for (const field of fields) {
    if (field.type !== 'message') continue
    const hint = field.value.find(item =>
      item.type === 'string' && item.value.includes('refmsg_type'),
    )?.value as string | undefined
    if (!hint) continue
    const refId = field.value.find(item => item.type === 'varint' && item.field === 1)?.value as bigint | undefined
    if (refId === undefined) continue
    return { referencedMessageId: refId.toString(), hint }
  }
  return undefined
}

function collectMessages (
  fields: WireField[],
  output: PushMessage[],
  rawTree: unknown,
  inherited: MessageContext = {},
): void {
  const strings = fields
    .filter((item): item is Extract<WireField, { type: 'string' }> => item.type === 'string')
    .map((item) => ({ field: item.field, value: item.value }))
  const context: MessageContext = { ...inherited }
  const envelopeCmd = fieldString(fields, 1)
  const envelopeInboxType = fieldString(fields, 5)
  if (envelopeCmd && envelopeInboxType && (envelopeInboxType === '0' || envelopeInboxType === '1')) {
    context.cmd = Number(envelopeCmd)
    context.inboxType = Number(envelopeInboxType)
  }
  const conversationId = strings.find(({ value }) => /^0:1:\d+:\d+$/.test(value))?.value ??
    strings.find(({ field, value }) => field === 1 && /^\d+$/.test(value))?.value
  if (conversationId) context.conversationId = conversationId
  const signalHead = fieldString(fields, 7)
  // 信令回执类帧（cmd=504 同步，50001/50013 等）布局异于普通推送：f7 为 5 位信令号、发送者在 f22
  //（普通推送 f7 是 15 位+ 的 sender uid，按位数区分防误判）
  const signalLayout = !!signalHead && /^\d{5}$/.test(signalHead)
  const senderUid = fieldString(fields, signalLayout ? 22 : 7)
  // 抖音 uid 至少 15 位数字；短数字（如回显帧中的 50013）是其他字段，不能当 sender
  if (senderUid && senderUid.length >= 15 && /^\d+$/.test(senderUid)) context.senderUid = senderUid
  const senderSecUid = fieldString(fields, 14)
  if (senderSecUid?.startsWith('MS4')) context.senderSecUid = senderSecUid
  // 盖楼检测：楼内回复帧正文 f1 直接为 thread_id，楼根藏在其 ext 的 s:add_ext。
  // 中间段是含连字符的 uuid，据此区分私聊会话 0:1:uid:uid（无连字符）。
  const directThreadId = strings.find(({ value }) => /^\d+:[0-9a-fA-F-]+-[0-9a-fA-F]+:\d+$/.test(value))?.value
  const threadExt = collectKeyValues(fields, 9)
  const addExt = parseContent(threadExt.get('s:add_ext') ?? '')
  const addThreadId = str(addExt?.['a:thread_id'])
  if (directThreadId) context.threadId = directThreadId
  if (addThreadId) context.threadId = addThreadId
  // 编辑元数据：编辑重推仍是普通消息帧，靠 ext 标记识别（s:edit_info 含 19 位 uid，需保精度解析）
  const editRaw = parseContent(threadExt.get('s:edit_info') ?? '', true)
  const editCount = threadExt.get('s:edit_count')
  if (editRaw?.['content_is_edited'] === true || (editCount && Number(editCount) > 0)) {
    context.editCount = editCount ? Number(editCount) : 1
    context.editInfo = {
      contentIsEdited: editRaw?.['content_is_edited'] === true,
      editorUid: str(editRaw?.['content_editor']),
      editTime: str(editRaw?.['content_edit_time']),
    }
    const orgType = threadExt.get('s:org_msg_type')
    if (orgType && /^\d+$/.test(orgType)) context.orgMsgType = Number(orgType)
  }
  const shortId = fieldString(fields, 5)
  if (!directThreadId && (conversationId || senderUid) && shortId && /^\d+$/.test(shortId)) {
    context.conversationShortId = shortId
  }
  if (context.threadId) {
    // f5 在楼内回复帧即 threadShortId；add_ext 数值可信度最高（楼根）；楼根自身 id 在 s:server_message_id
    const extServerId = threadExt.get('s:server_message_id')
    context.threadShortId = str(addExt?.['a:thread_short_id']) ||
      (directThreadId && shortId && /^\d+$/.test(shortId) ? shortId : undefined)
    context.isThreadRoot = addExt?.['a:is_thread_root_msg'] === '1'
    if (extServerId && /^\d+$/.test(extServerId)) context.serverMessageId = extServerId
    // 会话槽位被 thread_id 占用，末段即群会话短 id，据此还原会话标识
    if (!conversationId) {
      const tail = context.threadId.split(':')[2]
      if (tail && /^\d+$/.test(tail)) {
        context.conversationId = tail
        context.conversationShortId = context.conversationShortId ?? tail
      }
    }
  }
  const serverMessageId = fieldString(fields, 3)
  if ((conversationId || senderUid) && serverMessageId && /^\d+$/.test(serverMessageId)) context.serverMessageId = serverMessageId
  // 编辑重推的 f3 是推送载体 id，每次编辑都变；原消息 id 在 ext s:server_message_id，回填保证事件可关联原消息
  const editServerId = threadExt.get('s:server_message_id')
  if (context.editCount != null && editServerId && /^\d+$/.test(editServerId)) context.serverMessageId = editServerId
  const indexInConversation = fieldString(fields, 4)
  if ((conversationId || senderUid) && indexInConversation) context.indexInConversation = indexInConversation
  const indexInConversationV2 = fieldString(fields, 17)
  if ((conversationId || senderUid) && indexInConversationV2) context.indexInConversationV2 = indexInConversationV2
  const createTime = fieldString(fields, 10)
  if ((conversationId || senderUid) && createTime) context.createTime = createTime
  const reference = extractReference(fields)
  if ((conversationId || senderUid) && reference) context.reference = reference
  const contentField = fields.find((item): item is Extract<WireField, { type: 'string' }> =>
    item.type === 'string' && (item.field === 8 || item.field === 6) && item.value.trimStart().startsWith('{'),
  )
  const content = contentField?.value ?? ''
  // 无正文命令帧：content 为空、信息全在 ext（如 50005 会话删除/群解散），不放行则事件没有任何出口
  const bodylessCommand = !contentField && threadExt.size > 0 &&
    bodyless.has(Number(fieldString(fields, 6) ?? 7))
  if (context.conversationId && context.senderUid && (contentField || context.isThreadRoot || bodylessCommand)) {
    output.push({
      cmd: context.cmd ?? 500,
      ...(context.inboxType !== undefined ? { inboxType: context.inboxType } : {}),
      conversationId: context.conversationId,
      conversationShortId: context.conversationShortId ?? '',
      conversationType: /^\d+$/.test(context.conversationId) ? 2 : 1,
      senderUid: context.senderUid,
      ...(context.senderSecUid ? { senderSecUid: context.senderSecUid } : {}),
      content,
      messageType: signalLayout ? Number(signalHead) : Number(fieldString(fields, 6) ?? 7),
      ...(context.serverMessageId ? { serverMessageId: context.serverMessageId } : {}),
      ...(context.indexInConversation ? { indexInConversation: context.indexInConversation } : {}),
      ...(context.indexInConversationV2 ? { indexInConversationV2: context.indexInConversationV2 } : {}),
      ...(context.createTime ? { createTime: context.createTime } : {}),
      ...(context.reference ? { reference: context.reference } : {}),
      ...(context.threadId ? { threadId: context.threadId } : {}),
      ...(context.threadShortId ? { threadShortId: context.threadShortId } : {}),
      ...(context.isThreadRoot ? { isThreadRoot: context.isThreadRoot } : {}),
      ...(context.editCount != null ? { editCount: context.editCount } : {}),
      ...(context.editInfo ? { editInfo: context.editInfo } : {}),
      ...(context.orgMsgType != null ? { orgMsgType: context.orgMsgType } : {}),
      // ext 全文透出：撤回（s:target_server_message_id/s:recall_uid）等命令信息只在 f:9，content 常为空
      ...(threadExt.size > 0 ? { ext: Object.fromEntries(threadExt) } : {}),
      raw: { transport: 'android-frontier', content, wireTree: rawTree },
    })
  }
  for (const field of fields) {
    if (field.type === 'message') collectMessages(field.value, output, rawTree, context)
  }
}

/** Android Frontier payload 的无 schema 消息提取 */
export function extractAndroidPushes (payload: Uint8Array): PushMessage[] {
  const output: PushMessage[] = []
  const fields = decodeWire(payload)
  const tree = decodeWireTree(payload)
  collectMessages(fields, output, tree)
  const unique = new Map<string, PushMessage>()
  for (const message of output) {
    unique.set(`${message.serverMessageId ?? ''}|${message.conversationId}|${message.senderUid}|${message.content}`, message)
  }
  return [...unique.values()]
}
