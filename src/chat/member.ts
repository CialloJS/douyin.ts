import { LONG } from '../session/pb.js'
import { err } from '../error.js'
import { actionResponse } from './map.js'
import type { ConversationAddress, GroupMemberInfo, InboxContext } from '../types.js'

/** cmd=605 分页拉群成员；服务端按 cursor 推进，游标不前进即按上游返回终止 */
export async function getGroupMembers (
  ctx: InboxContext,
  address: ConversationAddress,
): Promise<GroupMemberInfo[]> {
  const members: GroupMemberInfo[] = []
  let cursor = '0'
  for (;;) {
    const decoded = await ctx.transport.sendCookieProto(
      605,
      address.inboxType ?? 0,
      '/v1/conversation/participants_list',
      {
        conversationParticipants: {
          conversationId: address.conversationId,
          conversationShortId: LONG.fromString(address.conversationShortId),
          conversationType: address.conversationType,
          cursor: LONG.fromString(cursor),
          limit: 100,
        },
      },
      ctx.deviceId,
    )
    const result = actionResponse(decoded, 'conversationParticipants')
    if (result.statusCode !== 0) return err(decoded)
    const payload = decoded['body'] as Record<string, unknown> | undefined
    const page = (payload?.['conversationParticipants'] as {
      participantsPage?: {
        participants?: Array<Record<string, unknown>>
        hasMore?: boolean
        cursor?: string | number | { toString (): string }
      }
    } | undefined)?.participantsPage
    for (const participant of page?.participants ?? []) {
      const uid = String(participant['userId'] ?? '')
      if (!uid) continue
      const secUid = String(participant['secUid'] ?? '')
      const alias = String(participant['alias'] ?? '')
      const sortOrder = String(participant['sortOrder'] ?? '')
      const leftBlockTime = String(participant['leftBlockTime'] ?? '')
      const ext = participant['ext']
      members.push({
        uid,
        role: Number(participant['role'] ?? 0),
        ...(secUid ? { secUid } : {}),
        ...(alias ? { alias } : {}),
        ...(sortOrder ? { sortOrder } : {}),
        ...(participant['blocked'] !== undefined ? { blocked: Number(participant['blocked']) } : {}),
        ...(leftBlockTime ? { leftBlockTime } : {}),
        ...(ext && typeof ext === 'object' ? { ext: ext as Record<string, string> } : {}),
      })
    }
    if (!page?.hasMore) return members
    const next = String(page.cursor ?? '')
    if (!next) return members
    cursor = next
  }
}
