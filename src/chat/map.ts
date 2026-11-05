import type { ActionResult, ChatMessage, GroupInfo, PrivateThread } from '../types.js'


/* ---------------------------------------------------------------------------
 * proto 响应映射（原 mappers.ts，仅收件箱内部使用）
 * ------------------------------------------------------------------------- */
export function isGroupConversationId (conversationId: string): boolean {
  return /^\d+$/.test(conversationId.trim())
}
export function mapProtoConversationListItem (raw: Record<string, unknown>): GroupInfo {
  const conversationId = String(raw['conversationId'] ?? '')
  const conversationType = Number(raw['conversationType'] ?? 0)
  // 群头像在 conversationCoreInfo.icon（对齐 douyin-im）；extInfo 仅补 name 等
  const core = raw['conversationCoreInfo'] as Record<string, unknown> | undefined
  const ext = raw['extInfo'] as Record<string, unknown> | undefined
  const setting = (raw['userSetting'] ?? raw['conversationSettingInfo']) as
    | Record<string, unknown>
    | undefined
  const memberBox = (raw['members'] ?? raw['firstPageParticipants']) as
    | { members?: Array<Record<string, unknown>>; participants?: Array<Record<string, unknown>> }
    | undefined
  const avatar = String(core?.['icon'] ?? ext?.['icon'] ?? core?.['avatar'] ?? ext?.['avatar'] ?? '')
  const ownerUid = String(ext?.['ownerUid'] ?? ext?.['owner'] ?? core?.['owner'] ?? '')
  // 群号落在 ConversationCoreInfo.ext 的 a:s_group_number（HAR 实证），会话列表 extInfo 同键兜底
  const coreExt = core?.['ext'] as Record<string, unknown> | undefined
  const groupNumber = String(coreExt?.['a:s_group_number'] ?? ext?.['a:s_group_number'] ?? '')
  // participants 键为 userId（对齐 douyin-im member['uid'] ?? member['userId']）
  const members = (memberBox?.members ?? memberBox?.participants ?? []).map((member) => {
    const secUid = String(member['secUid'] ?? '')
    return {
      uid: String(member['uid'] ?? member['userId'] ?? ''),
      role: Number(member['role'] ?? 0),
      ...(secUid ? { secUid } : {}),
    }
  }).filter((member) => member.uid && member.uid !== '0')
  return {
    conversationId,
    conversationShortId: String(raw['conversationShortId'] ?? ''),
    conversationType,
    isGroup: conversationType === 2 || isGroupConversationId(conversationId),
    name: String(ext?.['name'] ?? ''),
    ...(avatar ? { avatar } : {}),
    ...(ownerUid && ownerUid !== '0' ? { ownerUid } : {}),
    lastMessageTime: Number(setting?.['lastMsgTime'] ?? 0),
    members,
    ...(groupNumber ? { groupNumber } : {}),
    // ticket 只随 610 详情下发（列表接口不回填），未取到时保持缺省
    ...(raw['ticket'] ? { ticket: String(raw['ticket']) } : {}),
  }
}

/** 从 conversationId 解析对端 uid（私信格式 0:1:{uid_a}:{uid_b}） */
export function parsePeerFromConversationId (conversationId: string, myUid: string): string {
  const parts = conversationId.split(':')
  if (parts.length >= 4 && parts[1] === '1') {
    const uidA = parts[2]!
    const uidB = parts[3]!
    if (uidA === myUid) return uidB
    if (uidB === myUid) return uidA
    return uidB
  }
  return ''
}

/** 从 conversation 元数据构建 thread（peer 资料取 firstPageParticipants/userInfo 的 alias） */
export function mapProtoConversationMeta (
  conv: Record<string, unknown>,
  messages: Record<string, unknown>[],
  myUid: string,
): PrivateThread {
  const threadId = (conv['conversationId'] as string) ?? ''
  const conversationType = (conv['conversationType'] as number) ?? 1
  const peerUid = parsePeerFromConversationId(threadId, myUid)

  const participantPage = (conv['firstPageParticipants'] ?? conv['members']) as
    | { members?: Array<Record<string, unknown>>; participants?: Array<Record<string, unknown>> }
    | undefined
  const userInfo = conv['userInfo'] as Record<string, unknown> | undefined
  const candidates = participantPage?.participants ?? participantPage?.members ?? []
  const peerMember = candidates.find(
    (member) => String(member['userId'] ?? member['uid'] ?? '') === peerUid,
  )
  const peerInfo = peerMember ??
    (String(userInfo?.['userId'] ?? userInfo?.['uid'] ?? '') === peerUid ? userInfo : undefined)
  const peerSecUid = String(peerInfo?.['secUid'] ?? '')
  const peerNick = String(peerInfo?.['alias'] ?? peerInfo?.['nickname'] ?? '')

  const thread: PrivateThread = {
    threadId,
    ...(conv['conversationShortId'] != null
      ? { conversationShortId: String(conv['conversationShortId']) }
      : {}),
    conversationType,
    peer: {
      uid: peerUid,
      nickname: peerNick,
      ...(peerSecUid ? { secUid: peerSecUid } : {}),
    },
    unreadCount: Number(conv['badgeCount'] ?? conv['unreadCount'] ?? 0),
    updateTime: Number(
      (conv['extInfo'] as Record<string, unknown> | undefined)?.['lastActiveTime'] ?? 0,
    ),
    ...(conv['inboxType'] != null ? { inboxType: conv['inboxType'] as number } : {}),
  }

  const lastMsg = messages.find((m) => (m['conversationId'] as string) === threadId)
  if (lastMsg) {
    thread.lastMessage = mapProtoMessage(lastMsg)
    if (!thread.updateTime) thread.updateTime = thread.lastMessage.createTime
  }

  return thread
}

/** 从单条 message 记录构建 thread（无 conversations 字段时） */
export function mapProtoConversation (raw: Record<string, unknown>, myUid: string): PrivateThread {
  const threadId = (raw['conversationId'] as string) ?? ''
  const conversationType = (raw['conversationType'] as number) ?? 1
  const peerUid = parsePeerFromConversationId(threadId, myUid) ||
    (conversationType === 1 ? String(raw['sender'] ?? '') : '')
  const ext = raw['ext'] as Record<string, string> | undefined
  const thread: PrivateThread = {
    threadId,
    ...(raw['conversationShortId'] != null
      ? { conversationShortId: String(raw['conversationShortId']) }
      : {}),
    conversationType,
    peer: {
      uid: peerUid,
      nickname: '',
      ...(raw['secSender'] && String(raw['sender']) === peerUid
        ? { secUid: String(raw['secSender']) }
        : {}),
    },
    unreadCount: 0,
    updateTime: (raw['createTime'] as number) ?? 0,
    ...(ext?.['s:is_stranger'] === 'true' ? { isStranger: true } : {}),
  }
  if (raw['content']) {
    thread.lastMessage = mapProtoMessage(raw)
  }
  return thread
}
export function dedupeThreads (threads: PrivateThread[]): PrivateThread[] {
  const byId = new Map<string, PrivateThread>()
  for (const t of threads) {
    const prev = byId.get(t.threadId)
    if (!prev || t.updateTime >= prev.updateTime) {
      byId.set(t.threadId, t)
    }
  }
  return [...byId.values()]
}
export function mapProtoMessage (raw: Record<string, unknown>): ChatMessage {
  const senderSecUid = String(raw['secSender'] ?? '')
  const indexInConversation = String(raw['indexInConversation'] ?? '')
  const indexInConversationV2 = String(raw['indexInConversationV2'] ?? '')
  return {
    msgId: String(raw['serverMessageId'] ?? ''),
    threadId: (raw['conversationId'] as string) ?? '',
    senderUid: String(raw['sender'] ?? ''),
    ...(senderSecUid ? { senderSecUid } : {}),
    content: (raw['content'] as string) ?? '',
    msgType: (raw['messageType'] as number) ?? 0,
    createTime: (raw['createTime'] as number) ?? 0,
    status: (raw['status'] as number) ?? 0,
    ...(indexInConversation ? { indexInConversation } : {}),
    ...(indexInConversationV2 ? { indexInConversationV2 } : {}),
  }
}

interface ActionBody {
  status?: number
  extraInfo?: string
  checkCode?: number | string
  checkMessage?: string
}
export function parseActionCheckMessage (value: string): { parsed: boolean; code?: number; message?: string } {
  if (!value.trim()) return { parsed: false }
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>
    const rawCode = parsed['status_code'] ?? parsed['statusCode']
    const code = rawCode === undefined ? undefined : Number(rawCode)
    const message = [
      parsed['status_msg'],
      parsed['statusMsg'],
      parsed['tips'],
      parsed['toast'],
      parsed['message'],
    ].map((item) => String(item ?? '')).find(Boolean)
    return {
      parsed: true,
      ...(code !== undefined && Number.isFinite(code) ? { code } : {}),
      ...(message ? { message } : {}),
    }
  } catch {
    return { parsed: false }
  }
}

/** Desktop Cookie 会话动作统一响应归一 */
export function actionResponse (
  decoded: Record<string, unknown>,
  bodyKey?: string,
): ActionResult {
  const envelopeStatus = Number(decoded['statusCode'] ?? 0)
  const payload = decoded['body'] as Record<string, unknown> | undefined
  const body = (bodyKey ? payload?.[bodyKey] : undefined) as ActionBody | undefined
  const actionStatus = Number(body?.status ?? 0)
  const checkMessage = String(body?.checkMessage ?? '')
  const checkDetail = parseActionCheckMessage(checkMessage)
  const checkCode = checkDetail.code ?? Number(body?.checkCode ?? 0)
  const statusCode = envelopeStatus || checkCode || actionStatus
  const statusMsg = [
    checkDetail.message,
    checkDetail.parsed ? '' : checkMessage,
    body?.extraInfo,
    decoded['errorDesc'],
  ]
    .map((value) => String(value ?? ''))
    .find(Boolean) ?? ''
  return {
    statusCode,
    statusMsg,
    ...(checkCode ? { checkCode } : {}),
  }
}
