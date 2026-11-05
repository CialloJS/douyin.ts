import { LONG } from '../session/pb.js'
import { err } from '../error.js'
import { mapProtoMessage } from './map.js'
import type { ChatMessage, ConversationAddress, InboxContext } from '../types.js'

/** cmd=301 会话历史消息 */
export async function getChatHistory (
  ctx: InboxContext,
  options: ConversationAddress & { cursor?: number; count?: number },
): Promise<ChatMessage[]> {
  const decoded = await ctx.transport.sendCookieProto(
    301,
    1,
    '/v1/message/get_by_conversation',
    {
      conversationMessages: {
        conversationId: options.conversationId,
        conversationType: options.conversationType,
        conversationShortId: LONG.fromString(options.conversationShortId),
        direction: 1,
        anchorIndex: options.cursor ?? 0,
        limit: options.count ?? 20,
      },
    },
    ctx.deviceId,
  )
  const statusCode = Number(decoded['statusCode'] ?? 0)
  if (statusCode !== 0) return err(decoded)
  const messages = (decoded['body'] as Record<string, unknown> | null)?.['conversationMessages'] as
    | { messages?: unknown[] }
    | null
  return (messages?.messages ?? []).map((row) => mapProtoMessage(row as Record<string, unknown>))
}
