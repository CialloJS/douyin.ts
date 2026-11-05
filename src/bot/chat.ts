import { getChatHistory } from '../chat/history.js'
import { listConversationsByCookie } from '../chat/list.js'
import { getInfoList } from '../chat/info.js'
import { deleteConversation, setConversationSetting } from '../chat/group.js'
import { getStrangerList } from '../contact/stranger.js'
import { getReadIndex, getMinIndex, batchReadIndex } from '../inbox/cursor.js'
import { getUserMessage, clientAck, strangerConversations } from '../message/query.js'
import { readSwitch } from '../live/active.js'
import { toAddress } from './address.js'
import type { Bot } from './bot.js'
import type {
  ActionResult, BotMessage, ChatMessage, ConversationSettingInput, GroupInfo,
  MinIndexRow, ReadIndexRow, StrangerInfo, UserMessageQuery,
} from '../types.js'

export class Chat {
  constructor (private readonly bot: Bot) {}

  history (chatId: string, opts: { cursor?: number; count?: number } = {}): Promise<ChatMessage[]> {
    return getChatHistory(this.bot.ctx().inbox, { ...toAddress(chatId), ...opts })
  }

  async strangers (): Promise<StrangerInfo[]> {
    const list = await getStrangerList(this.bot.ctx().inbox)
    this.bot.rememberNicks(list)
    return list
  }

  /** 会话列表（旧 Cookie 通道，保留备用） */
  list (options: { cursor?: number; count?: number } = {}): Promise<GroupInfo[]> {
    return listConversationsByCookie(this.bot.ctx().inbox, options)
  }

  /** 会话详情（ticket/未读/成员），映射对齐列表会话 */
  info (chatId: string): Promise<GroupInfo[]> {
    return getInfoList(this.bot.ctx().inbox, [toAddress(chatId)])
  }

  /** 会话成员已读游标（cmd=2000） */
  readIndex (chatId: string): Promise<ReadIndexRow[]> {
    return getReadIndex(this.bot.ctx().inbox, toAddress(chatId))
  }

  /** 会话成员最小同步游标（cmd=2001，增量拉取起点） */
  minIndex (chatId: string): Promise<MinIndexRow[]> {
    return getMinIndex(this.bot.ctx().inbox, toAddress(chatId))
  }

  /** 按 uid 消息区间查询（cmd=2048，语义不完整返回原始结构） */
  userMessageStat (req: UserMessageQuery = {}): Promise<Record<string, unknown>> {
    return getUserMessage(this.bot.ctx().inbox, req)
  }

  /** 消息回执确认（cmd=2010） */
  ack (chatId: string, serverMessageId: string): Promise<ActionResult> {
    return clientAck(this.bot.ctx().inbox, { serverMessageId, conversationShortId: toAddress(chatId).conversationShortId })
  }

  /** 陌生人会话列表（服务端限流 409 时 statusMsg 会给出原因） */
  strangerConversations (): Promise<ActionResult> {
    return strangerConversations(this.bot.ctx().inbox, {})
  }

  /** 将一批入站消息标记已读（会话侧收到 50013 已读回执的依据） */
  readSwitch (chatId: string, msgs: BotMessage[]): Promise<void> {
    const addr = toAddress(chatId)
    return readSwitch(this.bot.ctx().http, msgs
      .filter(m => m.serverMessageId)
      .map(m => ({
        msgId: m.serverMessageId as string,
        convId: addr.conversationId,
        convShortId: addr.conversationShortId,
        createTime: Number(m.createTime ?? 0),
        convType: addr.conversationType,
      })))
  }

  /** 删除会话（cmd=603） */
  delete (chatId: string): Promise<ActionResult> {
    return deleteConversation(this.bot.ctx().inbox, toAddress(chatId))
  }

  /** 会话设置：置顶/免打扰/收藏（cmd=921） */
  setting (chatId: string, input: ConversationSettingInput): Promise<ActionResult & { setting?: Record<string, unknown> }> {
    return setConversationSetting(this.bot.ctx().inbox, toAddress(chatId), input)
  }

  /** 批量查所有成员已读游标（cmd=2038） */
  batchReadIndex (chatId: string): Promise<ActionResult> {
    return batchReadIndex(this.bot.ctx().inbox, toAddress(chatId))
  }
}
