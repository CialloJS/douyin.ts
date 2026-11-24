/** App 会话语义：会话、历史消息、已读游标等 protobuf 查询，经 IM 加密封装下发 */
import { DOMAIN, rest } from './rest.js'
import { pbQuery } from './pb.js'
import { normalizeDesktopTextMessageContent } from '../message/content.js'
import { wire } from './wire.js'
import type { Im } from './im.js'
import type { Dev, Ids } from './types.js'
import type { MsgBody } from '../types.js'

type Query = Record<string, string | number>

export interface ConvId {
  conversationId?: string
  /** int64 用字符串传，避免超过 2^53 精度丢失 */
  shortId?: string | number
  type?: number
}

export interface ConvPage {
  type?: number
  cursor?: string | number
  sort?: number
  limit?: number
}

export interface HistoryOpts extends ConvId {
  direction?: number
  anchor?: string | number
  limit?: number
}

export interface ReadOpts extends ConvId {
  readIndex?: string | number
  readIndexV2?: string | number
  unread?: string | number
  totalUnread?: string | number
  badge?: number
  ticket?: string
}

export interface UserMsgOpts {
  /** 会话增量版本，首帧传 0 */
  version?: string | number
  cmdIndex?: string | number
  strangerVersion?: string | number
  readVersion?: string | number
  source?: string
  consultVersion?: string | number
  notifyVersion?: string | number
  threadVersion?: string | number
  threadReadVersion?: string | number
  needReadInfo?: boolean
  /** 控制类消息链路游标，由上一次响应回传 */
  chainIndex?: string | number
}

export interface SendOpts extends ConvId {
  /** 统一消息体，给定时自动推导 messageType 与 content */
  body?: MsgBody
  /** 纯文本或 JSON 内容，按 messageType 解释 */
  content?: string
  ext?: Record<string, string>
  messageType?: number
  clientMessageId?: string
  mentionedUsers?: Array<string | number>
  threadId?: string
  /** 引用回复 */
  ref?: {
    id?: string | number
    hint?: string
    rootId?: string | number
    rootIndex?: string | number
  }
}

export interface CreateOpts {
  type?: number
  users?: Array<string | number>
  /** 单聊不生效，群聊名称 */
  name?: string
  avatar?: string
  desc?: string
  bizExt?: Record<string, string>
  ext?: Record<string, string>
  idempotentId?: string
  persistent?: boolean
}

export interface AuditOpts {
  cursor?: string | number
  limit?: number
  shortId?: string | number
  /** 不清理未读 */
  keepUnread?: boolean
}

export interface StrangerOpts {
  cursor?: string | number
  source?: number
  scene?: number
}

export interface RecentStrangerOpts {
  latest?: string | number
  earliest?: string | number
  source?: string
  newUser?: number
  bizInfo?: string
}

export interface MemberOpts extends ConvId {
  cursor?: string | number
  limit?: number
}

export interface MarkOpts extends ConvId {
  cursor?: string | number
  limit?: number
  asc?: boolean
  actionType?: number
  tag?: string | number
  clearUnread?: boolean
}

export interface CmdOpts {
  /** 控制类消息版本游标 */
  version?: string | number
  reverse?: boolean
  source?: string
}

export interface RangeOpts extends ConvId {
  /** 会话内 v2 索引区间，闭区间 */
  min?: string | number
  max?: string | number
  direction?: number
}

export interface InitOpts {
  version?: string | number
  page?: number
}

export interface ThreadOpts {
  threadVersion?: string | number
  /** 一次取多少条盖楼会话 */
  threadLimit?: number
  /** 每个盖楼取多少条消息 */
  msgLimit?: number
}

export interface TimeOpts {
  shortId?: string | number
  earliest?: string | number
  cursor?: string | number
  limit?: number
}

export interface CmdRangeOpts {
  cmdIndex?: string | number
  size?: number
  direction?: number
  chainIndex?: string | number
}

export interface SpecifiedOpts {
  shortId?: string | number
  listType?: number
  offset?: string | number
  count?: number
}

export interface MsgMarkOpts extends ConvId {
  messageId: string | number
  action?: number
  actionType?: number
  sortTime?: string | number
  tag?: string | number
}

export interface ExtOpts extends ConvId {
  messageId: string | number
  ext?: Record<string, string>
  isEdited?: boolean
  content?: string
  messageType?: number
  ticket?: string
}

export interface DelOpts extends ConvId {
  index?: string | number
  indexV2?: string | number
  badge?: number
}

export interface ThreadSubOpts {
  threadId?: string
  threadShortId?: string | number
  status: number
}

export interface ReactOpts extends ConvId {
  messageId: string | number
  /** 表情键值，如 [爱心] */
  emoji: string
  /** 默认添加回应，false 取消 */
  enabled?: boolean
}

/** path 以真机抓包为准：get_read_index/get_min_index 在 /v3 下 */
const PATH = {
  list: '/v1/conversation/list',
  infos: '/v2/conversation/get_info_list',
  info: '/v2/conversation/get_info',
  history: '/v1/message/get_by_conversation',
  read: '/v3/conversation/mark_read',
  readIndex: '/v3/conversation/get_read_index',
  minIndex: '/v3/conversation/get_min_index',
  userMsg: '/v3/message/get_user_message',
  send: '/v1/message/send',
  create: '/v2/conversation/create',
  stranger: '/v1/stranger/get_conversation_list',
  audit: '/v1/conversation/get_audit_list',
  participantsRead: '/v1/conversation/batch_get_conversation_participants_readindex',
  recent: '/v3/message/get_recent_stranger_message/',
  participants: '/v1/conversation/participants_list',
  members: '/v1/conversation/get_member_list',
  memberBatch: '/v1/conversation/batch_get_member_list',
  mget: '/v1/conversation/mget_participants',
  marks: '/v1/message/pull_mark',
  cmds: '/v1/conversation/get_recent_cmd_conv',
  range: '/v1/message/get_message_by_index_v2_range/',
  init: '/v1/message/get_message_by_init',
  thread: '/v1/message/get_thread_message_by_init',
  msgById: '/v1/message/get_message_by_server_id',
  msgByIds: '/v1/message/get_messages_by_server_id_list',
  byTime: '/v1/message/get_from_conversation_by_time',
  mark: '/v1/message/mark',
  modifyExt: '/v1/message/modify_ext',
  cmdRange: '/v1/message/get_cmd_message_range',
  specified: '/v3/conversation/specified_message_list',
  favorite: '/v2/conversation/get_by_favorite',
  top: '/v2/conversation/get_by_top',
  batchRead: '/v2/conversation/batch_mark_read',
  batchDelete: '/v1/conversation/batch_delete',
  clearMsg: '/v2/conversation/clear_message',
  recentStrangerConv: '/v1/conversation/get_recent_stranger_conv',
  threadSub: '/v1/conversation/update_thread_subscribe_status',
}

/** protobufjs 的 keepCase=false 只认 camelCase，写 snake_case 会被静默丢弃 */
function ref (id: ConvId): Record<string, unknown> {
  return {
    conversationId: id.conversationId ?? '',
    conversationShortId: id.shortId,
    conversationType: id.type ?? 0,
  }
}

export class Conv {
  constructor (
    private readonly im: Im,
    private readonly dev: Dev,
    private readonly ids: Ids,
  ) {}

  private call (path: string, cmd: number, field: string, body: Record<string, unknown>, ok?: number[]): Promise<Record<string, unknown>> {
    return pbQuery(this.im, this.dev, this.ids, path, cmd, field, body, ok)
  }

  /** 会话列表（cmd=2006） */
  list (opts: ConvPage = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.list, 2006, 'conversationList', {
      listType: opts.type ?? 0,
      cursor: opts.cursor ?? 0,
      sortType: opts.sort ?? 0,
      limit: opts.limit ?? 20,
    })
  }

  /** 按 id 批量取会话详情（cmd=610） */
  infos (list: ConvId[]): Promise<Record<string, unknown>> {
    return this.call(PATH.infos, 610, 'getConversationInfoListV2', {
      conversationInfoList: list.map(ref),
    })
  }

  /** 单个会话详情（cmd=608） */
  info (id: ConvId): Promise<Record<string, unknown>> {
    return this.call(PATH.info, 608, 'getConversationInfoV2', ref(id))
  }

  /** 历史消息（cmd=301） */
  history (opts: HistoryOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.history, 301, 'conversationMessages', {
      ...ref(opts),
      direction: opts.direction ?? 0,
      anchorIndex: opts.anchor ?? 0,
      limit: opts.limit ?? 20,
    })
  }

  /** 标记已读（cmd=2002，body oneof 仍占 tag=604） */
  read (opts: ReadOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.read, 2002, 'markConversationRead', {
      ...ref(opts),
      readMessageIndex: opts.readIndex,
      readMessageIndexV2: opts.readIndexV2,
      convUnreadCount: opts.unread,
      totalUnreadCount: opts.totalUnread,
      readBadgeCount: opts.badge,
      ticket: opts.ticket ?? '',
    })
  }

  /** 各成员已读游标（cmd=2000） */
  readIndex (id: ConvId): Promise<Record<string, unknown>> {
    return this.call(PATH.readIndex, 2000, 'getReadIndex', ref(id))
  }

  /** 最小同步游标（cmd=2001） */
  minIndex (id: ConvId): Promise<Record<string, unknown>> {
    return this.call(PATH.minIndex, 2001, 'getMinIndex', ref(id))
  }

  /** 增量拉会话/消息并下发 cmd 版本游标（cmd=12048） */
  userMessage (opts: UserMsgOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.userMsg, 12048, 'getUserMessage', {
      version: opts.version ?? 0,
      cmdIndex: opts.cmdIndex ?? 1,
      strangerVersion: opts.strangerVersion,
      readVersion: opts.readVersion ?? 1,
      source: opts.source ?? '',
      consultVersion: opts.consultVersion ?? 1,
      notifyVersion: opts.notifyVersion,
      threadVersion: opts.threadVersion ?? 1,
      threadReadVersion: opts.threadReadVersion ?? 1,
      needRecentConvReadInfo: opts.needReadInfo,
      cmdMessageChainV2Index: opts.chainIndex ?? 1,
    })
  }

  /** 发送消息（cmd=100）：body 传统一消息体，或直接给 messageType + content */
  async send (opts: SendOpts): Promise<Record<string, unknown>> {
    const refMsg = opts.ref
    const w = opts.body && wire(opts.body, await this.im.uid(), opts.conversationId)
    const type = w?.messageType ?? opts.messageType ?? 7
    const content = normalizeDesktopTextMessageContent(w?.content ?? opts.content ?? '', type)
    return this.call(PATH.send, 100, 'sendMessage', {
      ...ref(opts),
      content,
      // @所有人 靠 ext 标记透传，缺省则服务端不识别
      ext: w?.atAll ? { 's:mentioned_users': '0', ...opts.ext } : opts.ext,
      messageType: type,
      clientMessageId: opts.clientMessageId ?? '',
      mentionedUsers: w?.atAll ? ['0'] : w?.mentionedUsers ?? opts.mentionedUsers,
      threadId: opts.threadId,
      refMsgInfo: refMsg && {
        referencedMessageId: refMsg.id,
        hint: refMsg.hint,
        rootMessageId: refMsg.rootId,
        rootMessageConvIndex: refMsg.rootIndex,
      },
    })
  }

  /** 创建会话（cmd=609） */
  create (opts: CreateOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.create, 609, 'createConversationV2', {
      conversationType: opts.type ?? 1,
      participants: opts.users,
      persistent: opts.persistent ?? true,
      idempotentId: opts.idempotentId ?? '',
      name: opts.name,
      avatarUrl: opts.avatar,
      description: opts.desc,
      bizExt: opts.bizExt,
      ext: opts.ext,
    })
  }

  /** 陌生人会话列表（外层 cmd=1001，body tag=1000） */
  strangerList (opts: StrangerOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.stranger, 1001, 'strangerConversationList', {
      cursor: opts.cursor ?? 0,
      source: opts.source ?? 0,
      scene: opts.scene ?? 0,
    })
  }

  /** 会话审核列表（cmd=2027） */
  auditList (opts: AuditOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.audit, 2027, 'getConversationAuditList', {
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 20,
      convShortId: opts.shortId,
      noClearUnread: opts.keepUnread ?? false,
    })
  }

  /** 批量查各成员已读游标（cmd=2038） */
  participantsReadIndex (id: ConvId): Promise<Record<string, unknown>> {
    return this.call(PATH.participantsRead, 2038, 'getConversationParticipantsReadIndex', {
      conversationId: id.conversationId ?? '',
      conversationShortId: id.shortId,
      getUserReadIndex: 0,
    })
  }

  /** 最近陌生人消息（cmd=12047） */
  recentStranger (opts: RecentStrangerOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.recent, 12047, 'getRecentStrangerMessage', {
      latestStrangerVersion: opts.latest,
      earliestStrangerVersion: opts.earliest,
      source: opts.source ?? '',
      newUser: opts.newUser ?? 0,
      bizInfo: opts.bizInfo,
    })
  }

  /** 会话参与者分页（cmd=605） */
  participants (opts: MemberOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.participants, 605, 'conversationParticipants', {
      ...ref(opts),
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 50,
    })
  }

  /** 会话成员列表（cmd=12060） */
  members (opts: MemberOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.members, 12060, 'getConversationMemberListBody', {
      ...ref(opts),
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 50,
    })
  }

  /** 批量取多个会话成员（cmd=12061） */
  membersBatch (list: MemberOpts[]): Promise<Record<string, unknown>> {
    return this.call(PATH.memberBatch, 12061, 'batchGetConversationMemberListBody', {
      batchMemberList: list.map(o => ({
        ...ref(o),
        cursor: o.cursor ?? 0,
        limit: o.limit ?? 50,
      })),
    })
  }

  /** 按 uid 精确取成员（cmd=654） */
  membersByUid (id: ConvId, users: Array<string | number>): Promise<Record<string, unknown>> {
    return this.call(PATH.mget, 654, 'mgetConversationParticipantsBody', {
      ...ref(id),
      participants: users,
    })
  }

  /** 按标记位增量拉消息（cmd=2037） */
  marks (opts: MarkOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.marks, 2037, 'pullMarkMessageBody', {
      ...ref(opts),
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 20,
      asc: opts.asc ?? false,
      actionType: opts.actionType ?? 0,
      tag: opts.tag,
      clearUnreadCount: opts.clearUnread ?? false,
    })
  }

  /** 最近控制类消息会话（cmd=12062） */
  cmds (opts: CmdOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.cmds, 12062, 'getRecentCmdConv', {
      cmdMessageConvVersion: opts.version ?? 0,
      reverse: opts.reverse ?? false,
      source: opts.source ?? '',
    })
  }

  /** 会话内控制类消息（cmd=2040） */
  cmdMessages (opts: CmdOpts = {}): Promise<Record<string, unknown>> {
    return this.call('/v1/message/get_cmd_message/', 2040, 'getCmdMessageBody', {
      cmdIndex: opts.version ?? 0,
      source: opts.source ?? '',
      newUser: 0,
    })
  }

  /** 按会话内 v2 索引区间取消息（cmd=2041） */
  range (opts: RangeOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.range, 2041, 'getMessageInfoByIndexV2RangeBody', {
      ...ref(opts),
      minIndexInConversationV2: opts.min,
      maxIndexInConversationV2: opts.max,
      direction: opts.direction ?? 0,
    })
  }

  /** 冷启动首屏消息（cmd=2043） */
  init (opts: InitOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.init, 2043, 'messageByInit', {
      version: opts.version ?? 0,
      page: opts.page ?? 0,
    })
  }

  /** 盖楼消息冷启动（cmd=2204） */
  thread (opts: ThreadOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.thread, 2204, 'threadMessageByInit', {
      threadVersion: opts.threadVersion ?? 0,
      threadLimit: opts.threadLimit ?? 20,
      msgLimit: opts.msgLimit ?? 10,
    })
  }

  /** 按服务端消息 id 取单条（cmd=211） */
  msg (id: ConvId, messageId: string | number, onlyStatus = false): Promise<Record<string, unknown>> {
    return this.call(PATH.msgById, 211, 'getMessageByIdBody', {
      ...ref(id),
      serverMessageId: messageId,
      onlyStatus,
    })
  }

  /** 按服务端消息 id 批量取（cmd=212） */
  msgs (id: ConvId, messageIds: Array<string | number>): Promise<Record<string, unknown>> {
    return this.call(PATH.msgByIds, 212, 'getMessagesByServerIdListBody', {
      ...ref(id),
      serverMessageIdList: messageIds,
    })
  }

  /** 按时间正序翻页取消息（cmd=310） */
  byTime (opts: TimeOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.byTime, 310, 'getConversationMessagesByTimeBody', {
      convShortId: opts.shortId,
      earliestTimestamp: opts.earliest,
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 20,
    })
  }

  /** 消息标记/取消标记（cmd=2036） */
  mark (opts: MsgMarkOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.mark, 2036, 'markMessageBody', {
      ...ref(opts),
      serverMessageId: opts.messageId,
      doAction: opts.action ?? 0,
      actionType: opts.actionType ?? 0,
      sortTime: opts.sortTime,
      tag: opts.tag ?? 0,
    })
  }

  /** 修改消息扩展与内容（cmd=2021） */
  modifyExt (opts: ExtOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.modifyExt, 2021, 'modifyMessageExtBody', {
      ...ref(opts),
      messageId: opts.messageId,
      ticket: opts.ticket ?? '',
      ext: opts.ext,
      isEdited: opts.isEdited ?? false,
      content: opts.content,
      messageType: opts.messageType,
    })
  }

  /** 控制类消息区间（cmd=12040） */
  cmdRange (opts: CmdRangeOpts = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.cmdRange, 12040, 'getCmdMessageRangeBody', {
      cmdIndexV2: opts.cmdIndex ?? 0,
      size: opts.size ?? 20,
      direction: opts.direction ?? 0,
      cmdMessageChainV2Index: opts.chainIndex,
    })
  }

  /** 指定类型消息列表（cmd=12050） */
  specified (opts: SpecifiedOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.specified, 12050, 'getConversationSpecifiedMessageListBody', {
      messageListType: opts.listType ?? 0,
      conversationShortId: opts.shortId,
      offset: opts.offset ?? 0,
      count: opts.count ?? 20,
    })
  }

  /** 收藏会话列表（cmd=611） */
  favorite (opts: { cursor?: string | number; limit?: number } = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.favorite, 611, 'getConversationInfoListByFavoriteV2Body', {
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 20,
    })
  }

  /** 置顶会话列表（cmd=612） */
  top (opts: { cursor?: string | number; limit?: number; type?: number } = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.top, 612, 'getConversationInfoListByTopV2Body', {
      cursor: opts.cursor ?? 0,
      limit: opts.limit ?? 20,
      conversationType: opts.type ?? 0,
    })
  }

  /** 批量标记已读（cmd=613） */
  batchRead (list: ReadOpts[]): Promise<Record<string, unknown>> {
    return this.call(PATH.batchRead, 613, 'batchMarkReadBody', {
      markReadRequests: list.map(o => ({
        ...ref(o),
        readMessageIndex: o.readIndex,
        readMessageIndexV2: o.readIndexV2,
        convUnreadCount: o.unread,
        totalUnreadCount: o.totalUnread,
        readBadgeCount: o.badge,
        ticket: o.ticket ?? '',
      })),
    })
  }

  /** 批量删除会话（cmd=619） */
  batchDelete (list: DelOpts[]): Promise<Record<string, unknown>> {
    return this.call(PATH.batchDelete, 619, 'batchDeleteConversationBody', {
      markDeleteRequests: list.map(o => ({
        ...ref(o),
        lastMessageIndex: o.index,
        lastMessageIndexV2: o.indexV2,
        badgeCount: o.badge,
      })),
    })
  }

  /** 清空会话消息（cmd=620） */
  clearMsg (opts: DelOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.clearMsg, 620, 'clearConversationMessageV2Body', {
      ...ref(opts),
      lastMessageIndex: opts.index,
      lastMessageIndexV2: opts.indexV2,
      lastMsgBadgeCount: opts.badge,
    })
  }

  /** 最近陌生人会话（cmd=12063） */
  recentStrangerConv (opts: { max?: string | number; min?: string | number; reverse?: boolean; source?: string } = {}): Promise<Record<string, unknown>> {
    return this.call(PATH.recentStrangerConv, 12063, 'getRecentStrangerConv', {
      maxVersion: opts.max,
      minVersion: opts.min,
      reverse: opts.reverse ?? false,
      source: opts.source ?? '',
    })
  }

  /** 盖楼订阅状态（cmd=2205） */
  threadSub (opts: ThreadSubOpts): Promise<Record<string, unknown>> {
    return this.call(PATH.threadSub, 2205, 'updateThreadSubscribeStatus', {
      threadId: opts.threadId ?? '',
      threadShortId: opts.threadShortId,
      status: opts.status,
    })
  }

  /** 表情回应（cmd=705）：key 以 se:<键值> 下发，幂等命中服务端回 statusCode=1 */
  async react (opts: ReactOpts): Promise<Record<string, unknown>> {
    return this.call('/v1/message/set_property', 705, 'modifyMessageProperty', {
      propertyList: [{
        conversationId: opts.conversationId ?? '',
        conversationShortId: opts.shortId,
        conversationType: opts.type ?? 1,
        serverMessageId: opts.messageId,
        clientMessageId: '',
        modifyPropertyContent: [{
          operation: opts.enabled === false ? 1 : 0,
          key: `se:${opts.emoji}`,
          value: '',
          idempotentId: await this.im.uid(),
        }],
      }],
      ticket: '',
    }, [0, 1])
  }

  /** 会话悬浮条是否展示 */
  floatingCheck (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/conversation/floating_bar/check', { host: DOMAIN.social, query })
  }

  /** 会话悬浮条配置 */
  floatingConfigs (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/conversation/floating_bar/configs', { host: DOMAIN.social, query })
  }

  /** 默认聊天背景图 */
  backgrounds (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/conversation/background_pictures/default/', { host: DOMAIN.social, query })
  }

  /** 会话场景信息（v2 路径） */
  scene (query?: Query): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v2/im/conversation/info/other/scene', { host: DOMAIN.social, query })
  }

  /** 会话附加信息 */
  other (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/conversation/info/other', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }

  /** 会话内可打开的小程序/应用列表 */
  openApps (body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return rest(this.im, '/aweme/v1/im/conversation/open_app/list', {
      host: DOMAIN.social,
      enc: 'zstd-json',
      body,
    })
  }
}
