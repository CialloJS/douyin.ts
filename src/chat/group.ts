import { LONG } from '../session/pb.js'
import { actionResponse } from './map.js'
import type {
  ActionResult,
  ConversationAddress,
  ConversationSettingInput,
  CreateGroupOptions,
  GroupInfo,
  InboxContext,
} from '../types.js'

export { getGroupMembers } from './member.js'

/** 会话动作在协议侧只差 cmd/路径/响应体键，集中成表避免逐个复制请求骨架 */
interface Action {
  cmd: number
  path: string
  key: string
  /** 固定 inboxType：少数动作不随入参地址（群名设置固定 1） */
  inbox?: number
}

const act = {
  add: { cmd: 650, path: '/v1/conversation/add_participants', key: 'conversationAddParticipants' },
  remove: { cmd: 651, path: '/v1/conversation/remove_participants', key: 'conversationRemoveParticipants' },
  leave: { cmd: 652, path: '/v1/conversation/leave', key: 'leaveConversation' },
  del: { cmd: 603, path: '/v1/conversation/delete', key: 'deleteConversation' },
  name: { cmd: 902, path: '/v1/conversation/set_conversation_core_info', key: 'setConversationCoreInfo', inbox: 1 },
  setting: { cmd: 921, path: '/v1/conversation/set_setting_info', key: 'setConversationSettingInfo' },
} as const satisfies Record<string, Action>

/** 地址三件套：短 id 为 int64，必须以 Long 下发 */
function addr (address: ConversationAddress): Record<string, unknown> {
  return {
    conversationId: address.conversationId,
    conversationShortId: address.conversationShortId
      ? LONG.fromString(address.conversationShortId)
      : undefined,
    conversationType: address.conversationType,
  }
}

/** 动作请求：地址公共字段 + 业务字段统一包在当前动作的响应体键下 */
async function send (
  ctx: InboxContext,
  action: Action,
  address: ConversationAddress,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return ctx.transport.sendCookieProto(
    action.cmd,
    action.inbox ?? address.inboxType ?? 1,
    action.path,
    { [action.key]: { ...addr(address), ...payload } },
    ctx.deviceId,
  )
}

function bodyOf (
  decoded: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  return (decoded['body'] as Record<string, unknown> | undefined)?.[key] as
    | Record<string, unknown>
    | undefined
}

/** cmd=650 拉人入群；响应回读成功/失败名单 */
export async function addGroupMembers (
  ctx: InboxContext,
  address: ConversationAddress,
  uids: string[],
): Promise<ActionResult & { success?: string[]; failed?: string[] }> {
  const decoded = await send(ctx, act.add, address, {
    participants: uids.map((uid) => LONG.fromString(uid)),
    bizExt: {
      invitation: JSON.stringify({
        invitee: { source_app_id: 6383 },
        invitor: { im_user_id: Number(ctx.platformUid) },
        source_type: 6,
      }),
      source_type: '6',
      ticket: '',
    },
  })
  const result = actionResponse(decoded, act.add.key)
  const body = bodyOf(decoded, act.add.key) as {
    successParticipants?: Array<{ toString (): string }>
    failedParticipants?: Array<{ toString (): string }>
  } | undefined
  return {
    ...result,
    ...(body?.successParticipants?.length ? { success: body.successParticipants.map(String) } : {}),
    ...(body?.failedParticipants?.length ? { failed: body.failedParticipants.map(String) } : {}),
  }
}

/** cmd=651 移出群成员 */
export async function removeGroupMembers (
  ctx: InboxContext,
  address: ConversationAddress,
  uids: string[],
): Promise<ActionResult> {
  const decoded = await send(ctx, act.remove, address, {
    participants: uids.map((uid) => LONG.fromString(uid)),
  })
  return actionResponse(decoded, act.remove.key)
}

/** cmd=652 退出群聊（响应为空 body） */
export async function leaveGroup (
  ctx: InboxContext,
  address: ConversationAddress,
): Promise<ActionResult> {
  const decoded = await send(ctx, act.leave, address, {})
  return actionResponse(decoded, act.leave.key)
}

/** cmd=603 删除会话（响应为空 body） */
export async function deleteConversation (
  ctx: InboxContext,
  address: ConversationAddress,
  options: { lastMessageIndex?: string } = {},
): Promise<ActionResult> {
  const decoded = await send(ctx, act.del, address, {
    lastMessageIndex: LONG.fromString(options.lastMessageIndex ?? '0'),
    badgeCount: 0,
  })
  return actionResponse(decoded, act.del.key)
}

/** cmd=902 设置群名 */
export async function setGroupName (
  ctx: InboxContext,
  address: ConversationAddress,
  name: string,
): Promise<ActionResult> {
  const decoded = await send(ctx, act.name, address, { name, isNameSet: true })
  return actionResponse(decoded, act.name.key)
}

/** cmd=921 会话设置（置顶/免打扰/收藏），响应回读完整设置 */
export async function setConversationSetting (
  ctx: InboxContext,
  address: ConversationAddress,
  input: ConversationSettingInput,
): Promise<ActionResult & { setting?: Record<string, unknown> }> {
  const decoded = await send(ctx, act.setting, address, {
    ...(input.setStickOnTop != null ? { setStickOnTop: input.setStickOnTop } : {}),
    ...(input.setMute != null ? { setMute: input.setMute } : {}),
    ...(input.setFavorite != null ? { setFavorite: input.setFavorite } : {}),
  })
  const result = actionResponse(decoded, act.setting.key)
  const setting = bodyOf(decoded, act.setting.key)?.['conversationSettingInfo'] as
    | Record<string, unknown>
    | undefined
  return { ...result, ...(setting ? { setting } : {}) }
}

/** cmd=609 创建群聊，返回创建出的会话 */
export async function createGroup (
  ctx: InboxContext,
  options: CreateGroupOptions,
): Promise<ActionResult & { group?: GroupInfo }> {
  const name = options.name ?? ''
  const description = options.description ?? ''
  const decoded = await ctx.transport.sendCookieProto(
    609,
    1,
    '/v2/conversation/create',
    {
      createConversationV2: {
        conversationType: 2,
        participants: options.participantUids.map((uid) => LONG.fromString(uid)),
        name,
        description,
        bizExt: {
          group_type: '1000',
          show_at_profile: '1',
          group_name: name,
          group_desc: description,
        },
        ext: {
          'a:s_group_type': '1000',
          'a:s_group_category': '2',
        },
      },
    },
    ctx.deviceId,
  )
  const result = actionResponse(decoded, 'createConversationV2')
  const conv = (bodyOf(decoded, 'createConversationV2')?.['conversation']) as {
    conversationId?: string
    conversationShortId?: string | { toString (): string }
    conversationType?: number
  } | undefined
  if (!conv) return result
  return {
    ...result,
    group: {
      conversationId: String(conv.conversationId ?? ''),
      conversationShortId: String(conv.conversationShortId ?? ''),
      conversationType: Number(conv.conversationType ?? 2),
      isGroup: true,
      name,
      members: [],
      lastMessageTime: 0,
    },
  }
}
