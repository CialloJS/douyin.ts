import { LONG } from '../session/pb.js'
import { mapProtoConversationListItem } from './map.js'
import type { ConversationAddress, GroupInfo, InboxContext } from '../types.js'

/** cmd=610 按 id 批量查会话详情（ticket/未读/成员），映射对齐列表会话 */
export async function getInfoList (
  ctx: InboxContext,
  items: ConversationAddress[],
): Promise<GroupInfo[]> {
  if (items.length === 0) return []
  const decoded = await ctx.transport.sendCookieProto(
    610,
    items[0]?.inboxType ?? 0,
    '/v2/conversation/get_info_list',
    {
      getConversationInfoListV2: {
        conversationInfoList: items.map((item) => ({
          conversationId: item.conversationId,
          conversationShortId: LONG.fromString(item.conversationShortId || '0'),
          conversationType: item.conversationType,
        })),
      },
    },
    ctx.deviceId,
  )
  const payload = decoded['body'] as
    | { getConversationInfoListV2?: { conversationInfoList?: Record<string, unknown>[] } }
    | undefined
  return (payload?.getConversationInfoListV2?.conversationInfoList ?? []).map(
    mapProtoConversationListItem,
  )
}
