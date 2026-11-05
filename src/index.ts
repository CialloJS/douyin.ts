/** 抖音 Node SDK 唯一出口：运行时只导出 Bot/工具/登录/解密与错误类型 */

export { Bot } from './bot/bot.js'
export { chatIdOf } from './bot/address.js'
export { login } from './session/login/login.js'
export { decryptCencMp4 } from './media/cenc.js'
export { createLog } from './session/log.js'
export { SdkError, isErr } from './error.js'
export type { LoginOpts, Session, MfaInfo, QrStatus, VerifyWay } from './session/login/types.js'
export type {
  BotOpts, BotEvent, BotEventMap, BotMessage,
  Device, Log,
  InboundMessage, MsgBody, RecvBody, NoticeEvent, ReadEvent, RequestEvent, StatusEvent,
  GroupMemberChange, GroupMemberUpdate, VoipCallEvent, WsReconnectEvent, WsCloseEvent,
  FriendInfo, GroupInfo, GroupMemberInfo, StrangerInfo, FriendRequestInfo, GroupJoinRequestInfo,
  ChatMessage, ActionResult, RecallResult, ConversationAddress, UserProfile, ShareItem,
  ProfileDetail, AwemeDetail, OnlineItem, ReadSwitchItem, StrategyConfig, AccountInfo,
  Danmaku, Bubble, SocialUser, RelationPage, Notice, NoticeCount, NoticePage,
  DesktopSetting, UserSettings, ComplianceSetting, ReadIndexRow, MinIndexRow,
  UserMessageQuery, ClientAckItem, StrangerListOptions, GetPeerRequest, GetPeerResult, Card,
  ImageAsset, VideoAsset, FileUploadAsset, VideoSend, TextMention, LinkCard, UserCard,
  LocationCard, GroupCard, MediaInput, EncryptedVideoUrl, EmojiInfo, Sticker, StickerImage,
  StickerPage, StickerCollectResult, GroupShareInput, GroupShareResult,
} from './types.js'
