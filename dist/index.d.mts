//#region src/session/jar.d.ts
declare class Jar {
  private readonly store;
  constructor(initial?: string);
  get(name: string): string | undefined;
  has(name: string): boolean;
  set(name: string, value: string): void;
  delete(name: string): void;
  clear(): void;
  /** 导入 Cookie 请求头；响应 Set-Cookie 走 absorb 以支持过期删除 */
  merge(raw: string): void;
  header(): string;
  /** 接受独立或合并的 Set-Cookie（容忍 Expires 中的逗号）；max-age<=0 或已过期则删除 */
  absorb(raw: string, now?: number): void;
}
//#endregion
//#region src/live/transport.d.ts
/** HTTP protobuf 通道：Desktop Cookie 通道（发送/收件箱查询/动作/撤回/陌生人消息） */
declare class ProtoTransport {
  private readonly http;
  private readonly log;
  constructor(http: Http, log: Log);
  /** Desktop Cookie 通道（设备身份在 URL query，envelope headers 为空） */
  sendCookieProto(cmd: number, inboxType: number, endpoint: string, body: Record<string, unknown>, deviceId: string): Promise<Record<string, unknown>>;
  /** 原生通道（imapi.douyin.com：无 URL query、无 x-ss-stub，设备身份在 envelope f15 headers map） */
  sendNativeProto(cmd: number, inboxType: number, endpoint: string, body: Record<string, unknown>, deviceId: string): Promise<Record<string, unknown>>;
  private send;
  /** 两条通道共用的响应解码与失败诊断 */
  private decode;
}
//#endregion
//#region src/live/ws.d.ts
interface WsReconnectEvent {
  attempt: number;
  delayMs: number;
  code?: number;
  reason?: string;
}
interface WsCloseEvent {
  code?: number;
  reason?: string;
}
//#endregion
//#region src/app/types.d.ts
/** 设备画像：不含身份标识，身份统一放 Ids */
interface Dev {
  aid: number;
  appName: string;
  packageName: string;
  versionCode: number;
  versionName: string;
  manifestVersionCode: number;
  updateVersionCode: number;
  devicePlatform: string;
  os: string;
  osApi: number;
  osVersion: string;
  /** 系统 build 号：UA 与注册体的 release_build 必须一致，否则画像是两个系统 */
  build: string;
  /** rom_version：注册体与 ticket-guard 的 display-os-version 同源 */
  romVersion: string;
  resolution: string;
  dpi: number;
  deviceType: string;
  deviceBrand: string;
  cpuSupport64: string;
  hostAbi: string;
  channel: string;
  ac: string;
  mccMnc: string;
  ssmix: string;
  appTheme: string;
}
/** 设备标识：device_register 产出，调用方持久化后回传给 device()/login() */
interface Ids {
  device_id: string;
  iid: string;
  cdid: string;
  clientudid: string;
  openudid: string;
  klink_egdi: string;
  device_token: string;
  req_id: string;
  oaid: string;
  first_install: number;
  new_user?: number;
  device_id_str?: string;
  install_id_str?: string;
  dtrait_pk1?: string;
  dtrait_pk2?: string;
  dtrait_pk1_version?: string;
  dtrait_pk2_version?: string;
  dtrait_token?: string;
  dtrait_version?: number;
  bind_dtrait?: boolean;
  device_dtrait?: string;
  device_dtrait_token?: string;
  client_key?: string;
  source?: string;
  /** 注册时服务端下发的设备级 cookie（odin_tt 等），passport 会话缺它会被判 7 */
  cookie?: string;
}
/** 服务端二次验证方式（assist_ 前缀 = 安全手机） */
interface VerifyWay {
  verify_way?: string;
  /** 发起验证时必须回带的动作类型；缺失的方式无法自动完成 */
  act_type?: string | number;
  mobile?: string;
  sms_content?: string;
  channel_mobile?: string;
  description?: string;
  [key: string]: unknown;
}
interface MfaCtx {
  encrypt_uid?: string;
  not_login_ticket?: string;
  verify_ticket?: string;
  biz_params?: Record<string, unknown> | string;
  common_params?: Record<string, unknown> | string;
  event_params?: Record<string, unknown> | string;
  verify_ways?: VerifyWay[];
}
/** 登录成功 data 的常用字段 */
interface LoginData {
  user_id?: string;
  user_id_str?: string;
  uid?: string;
  sec_user_id?: string;
  session_key?: string;
  sessionid?: string;
  screen_name?: string;
  name?: string;
  avatar_url?: string;
  mobile?: string;
  has_password?: number;
  error_code?: number;
  description?: string;
  [key: string]: unknown;
}
interface CaptchaCredential {
  captcha?: string;
  verifyTicket?: string;
  sharkTicket?: string;
  mobileTicket?: string;
}
/** 设备注册/登录/IM 共用入参 */
interface AppOpts {
  /** 已有登录 Cookie（sessionid=...）；注入后 token()/info() 直接可用 */
  cookie?: string;
  /** 已持久化的设备标识；省略时 device() 自动注册 */
  ids?: Partial<Ids>;
  /** 覆盖设备画像字段 */
  dev?: Partial<Dev>;
  log?: Log;
}
//#endregion
//#region src/types.d.ts
interface Log {
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
}
interface Device {
  guid: string;
  deviceId: string;
  installId: string;
}
interface SelfInfo {
  uid?: string;
  nickname?: string;
  /** 真实头像(avatar_thumb.url_list 首个;passport 的 avatar_url 是 mosaic 占位) */
  avatar?: string;
}
/** 入站消息附 chatId 与发送者昵称，发消息直接回传 */
type BotMessage = InboundMessage & {
  chatId: string;
  senderNickname?: string;
};
type BotEventMap = {
  message: [BotMessage];
  /** 消息被编辑（编辑重推：原消息全文 + editCount/editInfo 元数据） */
  'message:edited': [BotMessage];
  notice: [NoticeEvent];
  request: [RequestEvent];
  /** 语音来电（messageType=50018；出站 msg.call 未支持，来电可感知） */
  voip: [VoipCallEvent];
  /** 单聊已读回执（messageType=50013） */
  read: [ReadEvent];
  /** 会话状态变更，高频（messageType=50001） */
  status: [StatusEvent];
  reconnecting: [WsReconnectEvent];
  close: [WsCloseEvent];
};
type BotEvent = keyof BotEventMap;
interface BotOpts {
  /** 登录 Cookie（login 返回或已登录浏览器复制） */
  cookie: string;
  /** 自身数字 uid；省略时 start() 自动获取 */
  userId?: string;
  userAgent?: string;
  timeout?: number;
  /** true 时自发消息也作为 message 事件下发（默认过滤） */
  selfMessage?: boolean;
  /**
   * 已持久化的设备身份（device_register 签发）；注入后跳过注册，避免每次启动重新注册。
   * 从上次 `bot.device` / `login()` 返回的 session.device 落盘复用即可。
   */
  device?: Device;
  /** App 域（扫码/短信登录、设备注册、IM）选项 */
  app?: AppOpts;
  log?: Log;
}
interface ConversationMember {
  uid: string;
  secUid?: string;
  role: number;
}
/** cmd 2006 返回的会话；纯数字 ID 且 type=2 的条目为群聊。 */
interface GroupInfo {
  conversationId: string;
  conversationShortId: string;
  conversationType: number;
  isGroup: boolean;
  name: string;
  avatar?: string;
  ownerUid?: string;
  lastMessageTime: number;
  members: ConversationMember[];
  /** 群号（ConversationCoreInfo.ext 的 a:s_group_number，客户端群资料页展示；私聊无） */
  groupNumber?: string;
  /** 会话校验凭证（proto ConversationV2.ticket，发群邀请卡 aweme_invite_card.ticket 同源） */
  ticket?: string;
}
interface ChatMessage {
  msgId: string;
  threadId: string;
  senderUid: string;
  senderSecUid?: string;
  content: string;
  msgType: number;
  createTime: number;
  status: number;
  indexInConversation?: string;
  indexInConversationV2?: string;
  [key: string]: unknown;
}
/** 好友（P2P 会话对端）信息 */
interface FriendInfo {
  uid: string;
  secUid?: string;
  nickname: string;
  conversationId: string;
  conversationShortId: string;
  lastMessage?: ChatMessage;
  lastMessageTime: number;
  unreadCount: number;
}
/** 陌生人会话信息 */
interface StrangerInfo {
  uid: string;
  nickname?: string;
  conversationId: string;
  conversationShortId: string;
  lastMessage?: ChatMessage;
  lastMessageTime: number;
  unreadCount: number;
}
/** 会话寻址（发送/撤回等共用）；type=50 为盖楼：conversationId 即 threadId 全串 */
interface ConversationAddress {
  conversationId: string;
  conversationShortId: string;
  conversationType: 1 | 2 | 50;
  inboxType?: number;
}
/** 作品分享卡片入参（messageType=8 / aweType=800）；itemId 与 uid 须对应真实作品，其余字段可选 */
interface ShareItem {
  /** 作品 id（itemId），服务端可能校验存在性 */
  itemId: string;
  /** 作者数字 uid */
  uid: string;
  /** 作者 sec uid（缺省不渲染作者头像/主页跳转） */
  secUid?: string;
  /** 作品标题（content_title），缺省用 itemId */
  title?: string;
  /** 作者昵称（content_name） */
  authorName?: string;
  /** 封面 URL（缺省卡片无封面图） */
  coverUrl?: string;
}
/** 引用消息元数据；在 cmd100 field 11 编码，正文仍使用普通文本 content。 */
interface SendMessageReference {
  referencedMessageId: string;
  hint: string;
  rootMessageId?: string;
  rootMessageConvIndex?: string;
}
/** sendBody 附加选项 */
interface SendBodyOptions {
  clientMessageId?: string;
  /** 引用元数据（refMsgInfo）；提供时本条消息为引用回复，与消息类型无关 */
  reference?: SendMessageReference;
}
interface SendMessageResponse {
  statusCode: number;
  statusMsg: string;
  serverMessageId?: string;
  clientMessageId?: string;
  /** 内容安全审核状态码（0=通过，非0=被拦截/需审核） */
  checkCode?: number;
}
interface RecallResult {
  statusCode: number;
  statusMsg: string;
  recalled: boolean;
}
interface ActionResult {
  statusCode: number;
  statusMsg: string;
  checkCode?: number;
}
interface GroupMemberInfo {
  uid: string;
  secUid?: string;
  nickname?: string;
  avatar?: string;
  role: number;
  alias?: string;
  sortOrder?: string;
  blocked?: number;
  leftBlockTime?: string;
  ext?: Readonly<Record<string, string>>;
}
declare enum GroupJoinRequestStatus {
  PENDING = 1,
  APPROVED = 2,
  REJECTED = 3,
  INVALID = 4
}
interface GroupJoinRequestInfo {
  requestId: string;
  applicantUid: string;
  applicantSecUid?: string;
  applicantNickname?: string;
  applicantAvatar?: string;
  groupShortId: string;
  conversationType: number;
  status: GroupJoinRequestStatus;
  reason?: string;
  inviterUid?: string;
  inviterSecUid?: string;
  createdAt?: string;
  modifiedAt?: string;
  moderatorUid?: string;
  ext?: Readonly<Record<string, string>>;
}
declare enum FriendRequestStatus {
  PENDING = 1,
  APPROVED = 2,
  REJECTED = 3,
  INVALID = 4
}
interface FriendRequestInfo {
  applicantUid: string;
  nickname?: string;
  avatar?: string;
  requestedAt?: string;
  status: FriendRequestStatus;
  message?: string;
  ext?: Readonly<Record<string, string>>;
}
/** 被引用消息（回复）信息：同 cmd=100 refMsgInfo 字段结构 */
interface MessageReference {
  referencedMessageId: string;
  hint: string;
  rootMessageId?: string;
}
/** WS 原始推送（解析前中间结构，等价参考 ImPushMessage） */
interface PushMessage {
  cmd: number;
  inboxType?: number;
  conversationId: string;
  conversationShortId: string;
  conversationType: number;
  senderUid: string;
  senderSecUid?: string;
  content: string;
  messageType: number;
  serverMessageId?: string;
  createTime?: string;
  indexInConversation?: string;
  indexInConversationV2?: string;
  reference?: MessageReference;
  /** 盖楼层 id（serverMessageId:clientMessageId:convShortId）；楼内消息均有 */
  threadId?: string;
  /** 盖楼短 id */
  threadShortId?: string;
  /** 盖楼根消息（messageType=50002、正文为空），楼内回复为普通文本消息 */
  isThreadRoot?: boolean;
  /** 消息编辑次数（ext s:edit_count）；编辑重推后 ≥1 */
  editCount?: number;
  /** 消息编辑元数据（ext s:edit_info，content_editor 为 19 位 uid 已保精度） */
  editInfo?: {
    contentIsEdited: boolean;
    editorUid: string;
    editTime: string;
  };
  /** 编辑前原始消息类型（ext s:org_msg_type；编辑重推时 messageType 可能变化，如根消息 org=7 而 messageType=50002） */
  orgMsgType?: number;
  /** f:9 key-values（s:xxx / a:xxx 上下文键；撤回帧的 target_server_message_id 等在此，content 常为空） */
  ext?: Readonly<Record<string, string>>;
  raw: Record<string, unknown>;
}
/** 入站业务消息：原始推送 + 收侧平铺消息体（type 判别，text 一律可读；媒体恒为资产形态，替代段数组） */
type InboundMessage = PushMessage & RecvBody;
type GroupMemberIncreaseSource = 'invite' | 'command' | 'qrcode' | 'duoshan' | 'apply' | 'search' | 'activity' | 'face-to-face' | 'circle' |
/** 被移出成员重新入群（50011 unblock diff 通道） */
'rejoin' |
/** 50001 command_type=7 成员变更帧（增删成员同步，无来源信息） */
'sync';
type GroupMemberDecreaseSource = 'kick' | 'leave' | 'sync';
interface NoticeUser {
  uid: string;
  secUid?: string;
  nickname?: string;
}
/** 语音/视频来电（messageType=50018 响铃信令，cmd=500 推送）。主叫=推送发送者；callInfo 含服务端 RTC 入会参数（individual.live_core_param 等）。
 * 区分语音/视频看 cameraOff：0=视频（开摄像头）、1=语音；voipType 恒为 1（1v1 通话形态，非媒体类型） */
interface VoipCallEvent {
  type: 'voip.call';
  conversationId: string;
  conversationType: number;
  callerUid: string;
  callId: string;
  roomId: string;
  /** 1v1 通话形态（实测恒为 1）；媒体类型看 cameraOff */
  voipType: number;
  callType: number;
  /** 0=视频通话 / 1=语音通话（发起时摄像头策略，实测为语音视频区分依据） */
  cameraOff: number;
  /** 原始 call_info（participants/individual/init_state 等全量字段） */
  callInfo: Record<string, unknown>;
}
/** 单聊已读回执（messageType=50013，cmd=504 推送；发送者视角显示为本机，读方取自 content.P2PSender） */
interface ReadEvent {
  type: 'read';
  conversationId: string;
  /** 已读方 uid */
  readerUid: string;
  /** 会话短 id */
  conShortId: string;
  /** 最新被读消息 id */
  messageId: string;
  /** 已读方游标 */
  readIndex: string;
}
/** 会话属性变更项（content.ext_data[i]；如 a:chat_theme 更换背景） */
interface StatusExtItem {
  key: string;
  value: string;
  version: number;
  opType: number;
}
/** 群成员资料变更明细（content.updated_participant_info[i]；role 0 普通 / 1 群主 / 2 管理员） */
interface GroupMemberUpdate {
  uid: string;
  role: number;
  secUid?: string;
  /** 群昵称：本帧下发即表示昵称被变更（有值=新昵称，空串=昵称被清空）；未下发表示本帧未涉及昵称 */
  alias?: string;
}
/** 群成员变更（command_type=7）：增删成员与角色/群主/群昵称变更；added/removed 均空而 updated 非空即成员资料变更 */
interface GroupMemberChange {
  /** 新增成员 uid（added_participant） */
  added: string[];
  /** 移除成员 uid（removed_participant） */
  removed: string[];
  /** 角色/群昵称等资料变更明细（modified_participant 对应 updated_participant_info） */
  updated: GroupMemberUpdate[];
  /** 变更前群主 uid（仅群主移交帧与 newOwnerId 成对带出） */
  oldOwnerId?: string;
  /** 变更后群主 uid（new_owner_id 非 0 即群主移交；普通帧无此键） */
  newOwnerId?: string;
}
/**
 * 会话状态变更（messageType=50001，高频，自发也下发）。command_type 实测取值：
 * 1/14 红点计数与已读游标同步、2 消息删除（message_id 指向被删消息）、6 会话属性变更（nameChange/avatarChange/ext_data 带具体属性）、7 群成员变更（memberChange）。
 */
interface StatusEvent {
  type: 'status';
  conversationId: string;
  conversationType: number;
  commandType: number;
  /** 未读计数；仅红点同步类（command_type=1/14）携带，删除/属性变更等缺省无 */
  unread?: number;
  /** 已读游标 */
  readIndex: string;
  /** 被删消息 id（command_type=2 携带，ext 字符串无损；content.message_id 为 JS 精度丢失版） */
  messageId?: string;
  /** 群名变更（command_type=6 且 ext_data 含 a:s_name_operator / a:group_name_lifecycle-event=name_change）；name 为新群名，operatorUid 来自 a:s_name_operator（缺省空） */
  nameChange?: {
    name: string;
    operatorUid: string;
  };
  /** 群头像变更（command_type=6 且 ext_data 含 a:group_avatar_user_set / s_user_set_avatar / a:ab_avatar）；icon 为新头像 URL，operatorUid 来自前者（ab_avatar 帧缺省空） */
  avatarChange?: {
    icon: string;
    operatorUid: string;
  };
  /** 群成员变更（command_type=7）：增删成员/角色变更/群主变更/群昵称变更 */
  memberChange?: GroupMemberChange;
  /** 会话属性变更（command_type=6 时带；如 a:chat_theme） */
  extData?: StatusExtItem[];
  /** 原始 content（conversation_id/read_index_v2/inbox_type 等全量字段） */
  raw: Record<string, unknown>;
}
/** 业务通知事件（撤回/好友增减/群成员增减/已读等；好友与入群申请分流到 RequestEvent） */
type NoticeEvent = {
  /** cmd=500 f500 property 推送的消息表情回应（ModifyPropertyBody 下发）。 */
  type: 'message.reaction';
  conversationId: string;
  serverMessageId: string;
  /** 抖音表态键值（se: 后文本，如 '[爱心]'） */
  emoji: string;
  /** 表态者 uid（idempotent_id） */
  operatorUid: string;
  /** true 添加 / false 移除 */
  isSet: boolean;
  raw: Record<string, unknown>;
} | {
  /** cmd508 的好友关系建立事实。 */
  type: 'friend.increase';
  peerUid: string;
  fromUid?: string;
  toUid?: string;
  content?: string;
  ext?: Readonly<Record<string, string>>;
  raw: Record<string, unknown>;
} | {
  /** cmd508 的好友关系解除事实。 */
  type: 'friend.decrease';
  peerUid: string;
  fromUid?: string;
  toUid?: string;
  content?: string;
  ext?: Readonly<Record<string, string>>;
  raw: Record<string, unknown>;
} | {
  type: 'conversation.read';
  conversationId: string;
  conversationType: number;
  readMessageIndex: string;
  readMessageIndexV2: string;
  raw: Record<string, unknown>;
} | {
  /** cmd504 NewP2PMessageNotify 的输入状态回推（客户端输入框有内容时周期上报）。 */
  type: 'conversation.typing';
  conversationId: string;
  /** 双人对话对端 uid */
  peerUid: string;
  peerSecUid?: string;
  /** 正在输入的成员 uid */
  senderUid: string;
  /** true 正在输入 / false 已停止 */
  typing: boolean;
  raw: Record<string, unknown>;
} | {
  type: 'conversation.update';
  conversationId: string;
  conversationType: number;
  raw: Record<string, unknown>;
} | {
  type: 'conversation.delete';
  conversationId: string;
  conversationType: number;
  /** 原始推送 ext（f:9 key-values；群解散导致的删除带 :dissolv_his 标记） */
  ext?: Readonly<Record<string, string>>;
  raw: Record<string, unknown>;
} | {
  type: 'message.recall';
  conversationId: string;
  conversationType: number;
  /** 被撤回消息 id（ext s:target_server_message_id） */
  serverMessageId?: string;
  /** 被撤回消息客户端 id（ext s:target_client_message_id） */
  targetClientMessageId?: string;
  /** 撤回操作者 uid（ext s:recall_uid） */
  recallUid?: string;
  /** 撤回者身份（ext s:recall_role，实测 1） */
  recallRole?: number;
  /** 原始推送 ext（f:9 key-values，撤回辅助信息） */
  ext?: Readonly<Record<string, string>>;
  raw: Record<string, unknown>;
} | {
  /** 群系统消息中的成员加入事实；一条消息可以包含多个成员。 */
  type: 'group.member-increase';
  conversationId: string;
  conversationShortId: string;
  conversationType: 2;
  source: GroupMemberIncreaseSource;
  members: NoticeUser[];
  operators: NoticeUser[];
  raw: Record<string, unknown>;
} | {
  /** 群系统消息中的成员离开事实；kick 的 passive_users 为离群成员，leave 的 active_users 为离群成员。 */
  type: 'group.member-decrease';
  conversationId: string;
  conversationShortId: string;
  conversationType: 2;
  source: GroupMemberDecreaseSource;
  members: NoticeUser[];
  operators: NoticeUser[];
  raw: Record<string, unknown>;
} | {
  /** messageType=1001, aweType=100110；设为管理员。 */
  type: 'group.admin';
  conversationId: string;
  conversationShortId: string;
  conversationType: 2;
  members: NoticeUser[];
  operators: NoticeUser[];
  enabled: true;
  raw: Record<string, unknown>;
} | {
  /** messageType=1001, aweType=100106；name 取不到时仍保留通知和 raw。 */
  type: 'group.name-change';
  conversationId: string;
  conversationShortId: string;
  conversationType: 2;
  name?: string;
  operators: NoticeUser[];
  raw: Record<string, unknown>;
} | {
  /** messageType=1001, aweType=100115；avatar 取不到时仍保留通知和 raw。 */
  type: 'group.avatar-change';
  conversationId: string;
  conversationShortId: string;
  conversationType: 2;
  avatar?: string;
  operators: NoticeUser[];
  raw: Record<string, unknown>;
} | {
  /** messageType=1001, aweType=100124；群被解散（解散者即推送发送方，无 active_users）。 */
  type: 'group.dismiss';
  conversationId: string;
  conversationShortId: string;
  conversationType: 2;
  /** 解散操作者（取推送发送方；取不到时缺省） */
  operatorUid?: string;
  operators: NoticeUser[];
  raw: Record<string, unknown>;
} | {
  type: 'im.command';
  conversationId: string;
  conversationType: number;
  messageType: number;
  content: string;
  raw: Record<string, unknown>;
};
/** 需要上层处理的请求事件（好友申请 / 入群申请） */
type RequestEvent = {
  /** cmd508 的 SendApply 信号；SDK 收到后刷新可处理的好友申请列表。 */
  type: 'friend.request';
  applicantUid: string;
  fromUid?: string;
  toUid?: string;
  content?: string;
  ext?: Readonly<Record<string, string>>;
  raw: Record<string, unknown>;
} | {
  /** cmd500 messageType=90001；SDK 收到后拉取审核列表再生成可操作 request。 */
  type: 'group.join-request';
  conversationId: string;
  conversationShortId: string;
  conversationType: number;
  requestId?: string;
  content: string;
  raw: Record<string, unknown>;
};
/** 合并转发节点（messageType=136 list_content + msg_ids） */
interface ForwardNode {
  /** 发送者 uid */
  uid: string;
  /** 发送者昵称 */
  nickname: string;
  /** 节点文本摘要（图片为 [图片] 等） */
  text: string;
  /** 节点消息类型（7 文本 / 27 图片 …） */
  msgType: number;
  /** 节点 aweType（700 文本 / 2702 图片 …） */
  aweType: number;
  /**
   * 节点消息 id（原消息 serverMessageId）。
   * 缺省即客户端伪造摘要：不注册云端记录，接收端点开无原文，仅外层昵称/文本可见。
   */
  msgId?: string;
  /** 发送者 secUid（如有） */
  secUid?: string;
  /** 节点发送时间 ms */
  createTime?: number;
}
/** 文件发送项：source 简写（自动上传，name 缺省从来源推断）或预上传 asset（uploadFile 返回值与 FileAsset 同形） */
type FileSend = {
  source: MediaInput;
  name?: string;
} | {
  asset: FileAsset;
};
/**
 * 消息统一结构基：type 判别类型，载荷字段平铺，收/发同构。
 * 仅媒体载荷按方向收窄（S='send' 可给输入源由 send 自动上传；S='recv' 恒为资产/资源形态可直接回传）。
 * text 为展示文本，一律可读；@ 提及并入 text 的 ats（含纯 @ 消息），@所有人 用 atAll（占位自动前置）。
 */
/** 接龙条目录入项（chains_entry_list[i]：e_c_u=提交者 uid、e_t=文本） */
interface ChainsEntry {
  uid: string;
  text: string;
}
/** 接龙消息（messageType=152，aweType=15200）：push_detail 即官方客户端展示文本 */
interface Chains {
  id: string;
  description: string;
  isStart: boolean;
  entries: ChainsEntry[];
}
/** 互动卡消息（messageType=110，aweType=110402 打卡邀请等）：im_dynamic_patch 为卡片载荷 */
interface Card {
  /** 卡片 key（patch.card_key，如 msg_guide / msg_preview） */
  key: string;
  /** 服务端卡片类型（patch.card_type，如 douyin_admin_msg_guide_invite / douyin_admin_msg_preview_ugc） */
  type: string;
  /** 卡片 id（patch.card_id；打卡卡 id 是嵌套 JSON 字符串，取内层 id） */
  id: string;
  /** 原互动类型（content.aweType，如引导卡 110402 / 打卡记录卡 110372；回传恢复原值） */
  aweType: number;
  /** 主文案（raw_data.content_middle_top / content_top 的 content） */
  title: string;
  /** 附属文案（raw_data.content_middle_content / content_middle 的 content） */
  desc: string;
  /** 按钮文案（raw_data.bottom / bottom_right 的 content） */
  button: string;
  /** 展示图片（raw_data.content_left / content_bottom 首位，url） */
  coverUrl: string;
  /** 官方签名（patch.sign，下发时生成；回传发送原样回填） */
  sign: string;
  /** 完整互动载荷（patch 原对象，收/发同构直接复用） */
  patch: Record<string, unknown>;
}
type RawBody<S extends 'send' | 'recv'> = {
  type: 'text';
  text: string;
  ats?: {
    uid: string;
    nickname?: string;
  }[];
  atAll?: boolean;
} | {
  type: 'image';
  text?: string;
  image: S extends 'send' ? ImageResource | MediaInput : ImageResource;
} | {
  type: 'video';
  text?: string;
  video: S extends 'send' ? VideoResource | VideoSend : VideoResource;
} | {
  type: 'file';
  text?: string;
  file: S extends 'send' ? FileAsset | FileSend : FileAsset;
} | {
  type: 'share';
  text?: string;
  share: ShareItem;
} | {
  type: 'userCard';
  text?: string;
  user: UserCard;
} | {
  type: 'forward';
  text?: string;
  nodes: ForwardNode[];
} | {
  type: 'audio';
  text?: string;
  audio: {
    urls: string[];
    uri: string;
  };
} | {
  type: 'emoji';
  text?: string;
  emoji: string;
} | {
  type: 'link';
  text?: string;
  link: LinkCard;
} | {
  type: 'chains';
  text?: string;
  chains: Chains;
} | {
  type: 'card';
  text?: string;
  card: Card;
} | {
  type: 'groupCard';
  text?: string;
  groupCard: GroupCard;
} | {
  type: 'location';
  text?: string;
  location: LocationCard;
} | {
  type: 'unknown';
  text?: string;
  raw: Record<string, unknown> | string;
};
/** 发侧消息体：统一走 bot.msg.send(chatId, body)，媒体可给输入源（send 自动上传） */
type MsgBody = RawBody<'send'>;
/** 收侧消息体：媒体恒为资产/资源形态，与 MsgBody 同构，可直接回传 send */
type RecvBody = RawBody<'recv'>;
/** 媒体输入源：http(s) URL、本地文件路径、base64 串或原始字节 */
type MediaInput = string | Uint8Array | ArrayBuffer;
interface ImageResource {
  oid: string;
  skey: string;
  md5: string;
  dataSize: number;
  width: number;
  height: number;
  originUrls?: string[];
  largeUrls?: string[];
  mediumUrls?: string[];
  thumbUrls?: string[];
  /** 图片格式（发侧上传脚本可由 oid 推断；收侧缺省） */
  format?: ImageFormat;
}
/** 图片上传资产（uploadImage 返回；字段与 ImageResource 同形，发侧要求齐全） */
interface ImageAsset {
  oid: string;
  skey: string;
  md5: string;
  dataSize: number;
  width: number;
  height: number;
  format?: ImageFormat;
}
/** 视频上传资产（uploadVideo 返回） */
interface VideoAsset {
  tkey: string;
  skey: string;
  md5: string;
}
/** 视频发送项：source 简写（自动上传/抽帧封面）或预上传 asset */
type VideoSend = {
  source: MediaInput;
  poster?: MediaInput | ImageAsset;
  width?: number;
  height?: number;
} | {
  asset: VideoAsset;
  poster?: ImageAsset;
  width?: number;
  height?: number;
};
/** batch_play_info 换取的加密视频地址（CENC 加密流，下载后用 decryptCencMp4 解密才能播放） */
interface EncryptedVideoUrl {
  mainUrl: string;
  backupUrl?: string;
  /** 签名过期时间（秒级时间戳），过期后 URL 失效需重取 */
  expireTime?: number;
}
interface VideoResource {
  tkey: string;
  skey: string;
  md5: string;
  width: number;
  height: number;
  checkPics: string[];
  poster?: ImageResource;
  /** 内置缩略图（WEBP base64 裸串，前缀 data:image/webp;base64, 即显；poster 签名 URL 过期时的兜底） */
  inlinePic?: string;
  /** 播放地址（事件下发前自动换取；过期后可 media.videoUrl(tkey) 重取） */
  url?: EncryptedVideoUrl;
}
type ImageFormat = 'webp' | 'jpeg' | 'png' | 'gif' | 'heic' | 'unknown';
interface LinkCard {
  url: string;
  title?: string;
  description?: string;
  coverUrl?: string;
}
interface UserCard {
  uid: string;
  secUid?: string;
  name?: string;
  avatarUrl?: string;
  desc?: string;
  followerCount?: string;
  coverItems?: string[];
  coverUrls?: string[];
}
/** 群聊邀请卡载荷（messageType=58 / aweme_invite_card）：向某会话发送「邀请加入某群」卡片 */
interface GroupCard {
  /** 被邀请群 id（conversation_id 与 conversation_short_id 同值下发） */
  conversationId: string;
  /** 群名（group_name，title/desc 展示文案内嵌） */
  groupName: string;
  /** 群图标 URL（group_icon.url_list 首位；缺省卡片无图） */
  iconUrl?: string;
  /** 群成员数（group_member_count） */
  memberCount?: number;
  /** 群主 uid（group_owner_uid） */
  ownerUid?: string;
  /** 群主 sec uid（sec_group_owner_uid） */
  ownerSecUid?: string;
  /** 群主昵称（group_owner_nickname，缺省空） */
  ownerNickname?: string;
  /** 邀请人 uid（from_uid；缺省用发送者自身） */
  fromUid?: string;
  /** 邀请人 sec uid（sec_from_uid），缺省省略 */
  fromSecUid?: string;
  /** 邀请人昵称（title/desc 文案；缺省用 uid） */
  fromNickname?: string;
  /** 群邀请凭证（aweme_invite_card.ticket）：经 chat.info 查目标群详情取得，服务端校验通过才派发卡片 */
  ticket?: string;
}
/** 位置消息载荷（messageType=502 POI 定位）：坐标 + 地点信息 + 封面图 */
interface LocationCard {
  /** 地点名（poi_name，text 展示） */
  name: string;
  /** 详细地址（poi_address） */
  address: string;
  /** 纬度 */
  latitude: number;
  /** 经度 */
  longitude: number;
  /** 模板 POI id（poi_id） */
  poiId?: string;
  /** 作品 POI id（aweme_poi_id） */
  awemePoiId?: string;
  /** 封面资源路径（cover_info.resource_url.uri） */
  uri?: string;
  /** 封面 URL 列表（cover_info.resource_url.url_list，发侧缺省用空数组） */
  urlList?: string[];
}
interface FileAsset {
  uri: string;
  skey: string;
  md5: string;
  name: string;
  dataSize: number;
}
/** 文本 @ 提及（richTextInfos 元数据；收侧无昵称，text 为发侧可选） */
interface TextMention {
  uid: string;
  /** 会话 id（官方 info.con_id，@ 归属会话） */
  conId?: string;
  text?: string;
  location: number;
  length: number;
}
interface InboxContext {
  transport: ProtoTransport;
  /** HTTP 链路（familiar/list 等 imdesktop 业务接口） */
  http: Http;
  /** Desktop IM 设备 ID（Cookie 通道 query 用） */
  deviceId: string;
  /** 平台数字 uid（thread 映射用） */
  platformUid: string;
}
interface ConversationSettingInput {
  setStickOnTop?: boolean;
  setMute?: boolean;
  setFavorite?: boolean;
}
interface CreateGroupOptions {
  /** 参与成员 uid（含创建者本人） */
  participantUids: string[];
  name?: string;
  description?: string;
}
interface VoiceCallResult {
  /** call 阶段 VoipInfo.channel_id / create 失败的 channel_id */
  channelId?: string;
  /** VoipStatus */
  status?: number;
  /** CallVoipResponseBody.check_code */
  checkCode?: string;
  /** CallVoipResponseBody.check_message */
  checkMessage?: string;
  /** create 阶段 VoipStatusCode（非 0 表示创建失败） */
  statusCode?: number;
}
interface ReplyOptions extends ConversationAddress {
  text: string;
  referencedMessageId: string;
  referencedMessageType: number;
  referencedUid: string;
  referencedSecUid?: string;
  nickname?: string;
  referencedText?: string;
  rootMessageId?: string;
  rootMessageConvIndex?: string;
  /** @所有人 引用回复：正文前置「@所有人 」占位，f9 mentioned_users=[0]（与 sendBody 同形态） */
  atAll?: boolean;
  /** @ 提及（正文 richTextInfos + f9 mentionedUsers）；缺省纯文本 */
  ats?: Array<{
    uid: string;
    nickname?: string;
  }>;
}
/** 会话成员已读游标行 */
interface ReadIndexRow {
  uid: string;
  /** 已读游标（微秒时间戳量级） */
  readIndex: number;
  extra?: number;
}
/** 会话成员最小同步游标行 */
interface MinIndexRow {
  uid: string;
  minIndex: number;
}
interface UserMessageQuery {
  /** uid 消息区间（int64 字符串） */
  startIndex?: string;
  messageType?: string;
  endIndex?: string;
  cursor?: string;
  inboxType?: number;
}
interface ClientAckItem {
  serverMessageId: string;
  clientMessageId?: string;
  conversationShortId?: string;
  /** 消息类型过滤，缺省 500（到达/已读确认） */
  messageType?: number;
  status?: number;
  count?: number;
  inboxType?: number;
}
interface StrangerListOptions {
  /** 分页游标 */
  cursor?: number;
  source?: number;
  scene?: number;
  inboxType?: number;
}
interface GetPeerRequest {
  appId?: number;
  sid?: number;
  taskType?: number;
  /** 原始键透传（vid/cdn_url/file_type/sfid 等），对齐服务端字段 */
  fileInfo: Record<string, unknown>;
}
interface GetPeerResult {
  status: number;
  fid: string;
  traceId: string;
  reqId: string;
  token: string;
  nodes: unknown[];
  multiNodes?: unknown[] | null;
  indexNum: number;
  countryCode: number;
  ispCode: number;
}
/** 通知分组未读数（notice/count 单组；401=互动，924=其他） */
interface NoticeCount {
  group: number;
  count: number;
  /** 红点未读数（含已读聚合） */
  dotCount: number;
  latestTime: number;
  showType: number;
  interactiveShowType: number;
}
/** 通知条目（notice/ 单条；type 决定 follow 等分组结构，未建模字段走 raw 透传） */
interface Notice {
  nid: string;
  type: number;
  createTime: number;
  raw: Record<string, unknown>;
}
/** 通知列表页 */
interface NoticePage {
  list: Notice[];
  hasMore: boolean;
  maxTime: number;
  minTime: number;
}
/** 作品详情摘要（aweme 结构繁复，仅提取常用字段，其余透传 raw） */
interface AwemeDetail {
  awemeId: string;
  desc?: string;
  createTime?: number;
  /** 播放地址列表（video.play_addr.url_list） */
  playUrls?: string[];
  /** 封面地址列表（video.cover.url_list） */
  coverUrls?: string[];
  author?: {
    secUid?: string;
    nickname?: string;
    avatar?: string;
  };
  raw: Record<string, unknown>;
}
/** 弹幕条目（danmaku/get_v2 单条，仅提取常用字段） */
interface Danmaku {
  id: string;
  itemId: string;
  /** 发送者数字 uid */
  userId: string;
  /** 出现时刻（毫秒偏移） */
  offsetTime: number;
  text: string;
  diggCount: number;
  showDigg: boolean;
}
/** 社交用户摘要（spotlight/relation 与 familiar/list 共用；未建模字段走 raw 透传） */
interface SocialUser {
  uid: string;
  secUid: string;
  nickname: string;
  avatar?: string;
  signature?: string;
  uniqueId?: string;
  followStatus: number;
  followerStatus: number;
  raw: Record<string, unknown>;
}
/** 气泡详情（bubble/detail_list 单条；resource 结构繁复，只提取预览图） */
interface Bubble {
  id: string;
  name: string;
  type: number;
  source: number;
  description?: string;
  /** 亮色预览图 */
  lightPreview?: string;
  /** 暗色预览图 */
  darkPreview?: string;
  /** 是否为用户当前使用中的气泡 */
  current: boolean;
  raw: Record<string, unknown>;
}
/** 好友/关注列表分页（spotlight 返回 top 侧分页字段） */
interface RelationPage {
  users: SocialUser[];
  hasMore: boolean;
  maxTime: number;
  minTime: number;
}
/** 官方表情资源（/aweme/v1/web/emoji/list/ 下发，id 为拼音资源名，name 与表态键值同源） */
interface EmojiInfo {
  /** 资源 id（如 weixiao / jinli） */
  id: string;
  /** 显示键值（如 [微笑]） */
  name: string;
  /** TOS 资源路径（tos-cn-i-tsj2vxp0zn/<hash>，hash 与官方面板小表情分区图片一致） */
  uri: string;
  /** CDN 直链（带签名时效，过期后可用 uri 重新换链） */
  urls: string[];
}
/** 贴纸图片（static 静态 / animate 动图，抖音 GIF 表情即动图贴纸） */
interface StickerImage {
  width: number;
  height: number;
  uri: string;
  urls: string[];
}
/** 表情贴纸（收藏/自定义/官方面板通用结构） */
interface Sticker {
  /** 贴纸 id（用 id_str 字符串，服务端 number 字段在 JS 中会丢精度） */
  id: string;
  /** sticker_type：如 2=表情贴纸 */
  type: number;
  /** 显示名（如 [微笑]，空串不返回） */
  name?: string;
  hash?: string;
  /** 来源标记（comment_emoji 等） */
  source?: string;
  /** 静态图 */
  static?: StickerImage;
  /** 动图（webp/gif 载体） */
  animate?: StickerImage;
}
/** 表情资源列表页（scenes 决定响应顶层键，统一收拢为此结构） */
interface StickerPage {
  list: Sticker[];
  total: number;
  cursor: number;
  done: boolean;
}
/** 收藏操作结果：成功收藏/取消的贴纸 id */
interface StickerCollectResult {
  ids: string[];
}
/** strategy/config:app 能力开关结果（决策树 + 动效资源包配置） */
interface StrategyConfig {
  decisionTrees?: Record<string, unknown>;
  interactiveResourceConfig?: Record<string, unknown>;
}
/** 用户公开资料（昵称/头像） */
interface UserProfile {
  nickname?: string;
  avatar?: string;
}
/** IM 用户信息（desktop im/user/info；未建模字段走 raw 透传） */
interface UserInfo {
  uid: string;
  secUid: string;
  nickname?: string;
  avatar?: string;
  signature?: string;
  shortId?: string;
  uniqueId?: string;
  followStatus?: number;
  followerStatus?: number;
  isBlock?: boolean;
  imActiveness?: number;
  raw: Record<string, unknown>;
}
/** 用户详细资料（profileScene/profileOther 共用；未建模字段走 raw 透传） */
interface ProfileDetail {
  uid: string;
  secUid: string;
  nickname?: string;
  signature?: string;
  avatar?: string;
  uniqueId?: string;
  followingCount?: number;
  followerCount?: number;
  followStatus?: number;
  followerStatus?: number;
  raw: Record<string, unknown>;
}
/** 当前 passport 账号详情(未建模字段走 raw 透传) */
interface AccountInfo {
  userId: string;
  secUserId: string;
  name?: string;
  screenName?: string;
  avatar?: string;
  mobile?: string;
  email?: string;
  gender?: number;
  hasPassword?: boolean;
  createTime?: number;
  raw: Record<string, unknown>;
}
/** 在线状态项（secUserId 维度） */
interface OnlineItem {
  secUserId: string;
  /** 最后活跃时间（秒时间戳），0 表示从未在线 */
  lastActiveTime: number;
}
/** 已读回执项（conv_short_id 透传原样，避免 int64 在 JSON 里丢精度） */
interface ReadSwitchItem {
  msgId: string;
  convId: string;
  convShortId: string | number;
  createTime: number;
  convType: number;
}
/** 桌面 IM 消息设置（im/desktop/setting/get） */
interface DesktopSetting {
  /** 消息提醒开关 */
  messageAlert: number;
  /** 显示消息详情开关（服务端字段拼写即 swtich） */
  showMessageDetail: number;
}
/** 账号综合设置（user/settings，字段庞大，未建模字段走 raw 透传） */
interface UserSettings {
  /** 私密账号等级 */
  chatSet: number;
  teenMode: number;
  isMinor: boolean;
  settingsVersion?: string;
  raw: Record<string, unknown>;
}
/** 合规/青少年模式设置（compliance/settings） */
interface ComplianceSetting {
  minorControlType: number;
  isMinor: boolean;
  teenMode: number;
  raw: Record<string, unknown>;
}
/** 群分享入参：邀请链接（自动解析 secret/group_id）或纯 secret + conversationId */
interface GroupShareInput {
  /** 邀请链接或链接中的 secret（AAED 前缀） */
  share: string;
  /** 群 conversationId；链接自带 group_id 时可省略 */
  conversationId?: string;
  /** 邀请卡场景（invite_card_scene），缺省 0 */
  scene?: number;
}
/** 群分享校验结果：发群邀请卡所需的 ticket 与群资料 */
interface GroupShareResult {
  ticket: string;
  conversationId: string;
  conversationShortId: string;
  name: string;
  desc: string;
  avatar?: string;
  memberCount: number;
  ownerUid?: string;
  ownerSecUid?: string;
  ownerNickname?: string;
  inviterUid?: string;
  inviterSecUid?: string;
  auditQuestion?: string;
}
interface FileUploadAsset {
  uri: string;
  skey: string;
  md5: string;
  name: string;
  dataSize: number;
}
type ImEventMap = {
  message: [message: InboundMessage];
  /** 消息被编辑（编辑重推：内容为编辑后全文，ext 带 editCount/editInfo） */
  'message:edited': [message: InboundMessage];
  notice: [notice: NoticeEvent];
  request: [request: RequestEvent];
  /** 语音来电（messageType=50018；出站未支持，来电可感知） */
  voip: [event: VoipCallEvent];
  /** 单聊已读回执（messageType=50013，发放于自发过滤之前） */
  read: [event: ReadEvent];
  /** 会话状态变更，高频（messageType=50001，发放于自发过滤之前） */
  status: [event: StatusEvent];
  reconnecting: [event: WsReconnectEvent];
  close: [event: WsCloseEvent];
};
type ImEvent = keyof ImEventMap;
//#endregion
//#region src/session/types.d.ts
/** data 与 text 并存：JSON 调用方取 data，HTML/protobuf 调用方取 text */
interface Res$1<T = unknown> {
  ok: boolean;
  status: number;
  headers: Headers;
  data: T;
  text: string;
}
interface ResBytes<T = Uint8Array> {
  ok: boolean;
  status: number;
  headers: Headers;
  data: T;
}
interface HttpOpts {
  /** 浏览器复制的 Cookie 或上一轮会话 */
  cookie?: string;
  /** 当前账号 uid，发消息/收件箱/上传链路使用 */
  userId?: string;
  userAgent?: string;
  /** 默认请求超时毫秒；init.signal 显式传入时优先生效 */
  timeout?: number;
  log?: Log;
}
//#endregion
//#region src/session/http.d.ts
/**
 * 抖音 HTTP 通道：Cookie/UA/超时封装 + Passport 请求头。
 * 签名（sign/qs/a_bogus）由调用方组装进 URL 后直发，本类不感知具体接口。
 */
declare class Http {
  readonly jar: Jar;
  readonly userId: string;
  readonly ua: string;
  readonly log: Log;
  bizTraceId: string;
  /** 服务端注册的桌面设备身份（登录时注入；'0' 表示未注册） */
  deviceId: string;
  installId: string;
  guid: string;
  private readonly timeout;
  private readonly portrait;
  constructor(opts?: HttpOpts);
  /** 注入 device_register 签发的设备身份 */
  setDevice(device: {
    deviceId: string;
    installId: string;
    guid: string;
  }): void;
  hasDevice(): boolean;
  /** Passport 请求头；imdesktop（桌面，含登录）/ creator（web）分流 */
  passportHeaders(url?: string): Record<string, string>;
  request(url: string, init?: RequestInit): Promise<Res$1<string>>;
  /** 只负责解码；状态与业务失败由调用方按原始响应决定如何交回 */
  json<T>(url: string, init?: RequestInit): Promise<Res$1<T>>;
  bytes(url: string, init?: RequestInit): Promise<ResBytes>;
  get(url: string, init?: RequestInit): Promise<Res$1<string>>;
  /** Passport form 链路：body 已是 urlencoded 串，默认补 Content-Type */
  post(url: string, body?: string, init?: RequestInit): Promise<Res$1<string>>;
  /** 媒体上传：body 原样透传，Content-Type 由调用方决定 */
  upload(url: string, body: NonNullable<RequestInit['body']>, init?: RequestInit): Promise<Res$1<string>>;
  private aidSignFor;
  private send;
  /** 吸收 Set-Cookie 与 msToken：会话跨请求自续 */
  private absorb;
}
//#endregion
//#region src/session/emitter.d.ts
declare class Emitter<M extends Record<string, unknown[]>> {
  private readonly map;
  on<K extends keyof M>(event: K, fn: (...args: M[K]) => void): void;
  off<K extends keyof M>(event: K, fn: (...args: M[K]) => void): void;
  protected emit<K extends keyof M>(event: K, ...args: M[K]): void;
}
//#endregion
//#region src/media/upload.d.ts
/** Cookie 鉴权 STS → 签名 VOD → TOS 上传工作流 */
declare class Uploader {
  private readonly vod;
  private readonly tos;
  constructor(http: Http, userId: string);
  uploadImage(data: Uint8Array): Promise<ImageAsset>;
  uploadVideo(data: Uint8Array): Promise<VideoAsset>;
  /** 文件上传（object 通道：public_file_config + GCM 服务端加密，≤10MiB） */
  uploadFile(data: Uint8Array, name: string): Promise<FileUploadAsset>;
}
//#endregion
//#region src/message/core.d.ts
/** 发送上下文：统一 HTTP cookie 通道（native ImOption profile）+ WS cmd411 输入状态通道 */
interface SendContext {
  transport: ProtoTransport;
  deviceId: string;
  log: Log;
  /** 直连 HTTP 客户端（云端接口：合并转发凭证/视频地址等） */
  http: Http;
  /** 账号 uid（cmd411 帧 envelope device_id） */
  userId: string;
  /** 浏览器 Cookie 串（cmd411 WS 握手鉴权） */
  cookies: string;
}
//#endregion
//#region src/bot/ctx.d.ts
interface Ctx {
  http: Http;
  userId: string;
  deviceId: string;
  cookies: string;
  log: Log;
  transport: ProtoTransport;
  uploader: Uploader;
  inbox: InboxContext;
  send: SendContext;
}
//#endregion
//#region src/bot/msg.d.ts
type StatusResult = {
  statusCode: number;
  statusMsg: string;
};
declare class Msg {
  private readonly bot;
  constructor(bot: Bot);
  /** 统一发送：type 判别一条消息；媒体输入源自动上传，收侧消息对象可直接回传当引用 */
  send(chatId: string, body: MsgBody, opts?: SendBodyOptions & {
    reply?: BotMessage;
  }): Promise<SendMessageResponse>;
  /** 编辑不支持：HTTP 复用原 cmid 会被服务端幂等去重，官方编辑走 App 专属通道 */
  edit(chatId: string, clientMessageId: string, body: MsgBody): Promise<SendMessageResponse>;
  /** 媒体输入源归一化：简写源先上传为资产，预上传 asset 原样透传 */
  private prepare;
  /** 上报输入状态（true 正在输入 / false 停止） */
  sendTyping(chatId: string, typing: boolean): Promise<boolean>;
  /** 发起语音通话（服务端无 VOIP 通道，返回 statusCode=-1） */
  call(chatId: string, calleeUid: string): Promise<VoiceCallResult>;
  /** 引用回复：任意消息类型均可引，body 可为文本或任意消息体；文本为空不发送 */
  reply(chatId: string, msg: BotMessage, body: string | MsgBody, opts?: Pick<ReplyOptions, 'atAll' | 'ats'>): Promise<SendMessageResponse>;
  recall(chatId: string, serverMessageId: string): Promise<RecallResult>;
  /** 表情回应：emoji 传抖音键值（如 '[爱心]'）或小表情 id（如 weixiao），isSet false 取消 */
  react(chatId: string, serverMessageId: string, emoji: string, isSet?: boolean): Promise<StatusResult>;
  /** 标记已读；msg 缺省读到底 */
  read(chatId: string, msg?: BotMessage): Promise<StatusResult>;
}
//#endregion
//#region src/bot/media.d.ts
declare class Media {
  private readonly bot;
  constructor(bot: Bot);
  /** 图片上传：url/路径/base64/字节均可 */
  image(input: MediaInput): Promise<ImageAsset>;
  /** 视频上传：url/路径/base64/字节均可 */
  video(input: MediaInput): Promise<VideoAsset>;
  /** 文件上传：名字缺省从来源推断 */
  file(input: MediaInput, name?: string): Promise<FileUploadAsset>;
  /** 用消息视频的 tkey 换加密 CDN 播放地址（CENC 流，需解密后才能播放） */
  videoUrl(tkey: string): Promise<EncryptedVideoUrl>;
  /** 按 awemeId 批量拉作品详情（视频/图文） */
  awemeDetail(awemeIds: string[], options?: {
    originType?: string;
    requestSource?: number;
    conversationShortId?: string;
  }): Promise<AwemeDetail[]>;
  /** CDN 传输节点调度（按文件信息选可用节点） */
  getPeer(req: GetPeerRequest): Promise<GetPeerResult>;
  /** 官方表情资源全量映射（id/键值/CDN 直链） */
  emojiList(): Promise<EmojiInfo[]>;
}
//#endregion
//#region src/bot/frd.d.ts
declare class Frd {
  private readonly bot;
  constructor(bot: Bot);
  /** 分页参数：cursor 起始游标，count 单页条数；缺省自动翻页拉全量 */
  list(options?: {
    cursor?: number;
    count?: number;
  }): Promise<Array<FriendInfo & {
    chatId: string;
  }>>;
  requests(status?: FriendRequestStatus): Promise<FriendRequestInfo[]>;
  approve(uid: string): Promise<ActionResult>;
  reject(uid: string): Promise<ActionResult>;
}
//#endregion
//#region src/bot/grp.d.ts
declare class Grp {
  private readonly bot;
  constructor(bot: Bot);
  /** 分页参数：cursor 起始游标，count 单页条数；缺省自动翻页拉全量 */
  list(options?: {
    cursor?: number;
    count?: number;
  }): Promise<Array<GroupInfo & {
    chatId: string;
  }>>;
  members(chatId: string): Promise<GroupMemberInfo[]>;
  /** 群入群申请；省略 chatId 查全部群 */
  requests(chatId?: string): Promise<GroupJoinRequestInfo[]>;
  approve(requestId: string): Promise<ActionResult & {
    request?: GroupJoinRequestInfo;
  }>;
  reject(requestId: string): Promise<ActionResult & {
    request?: GroupJoinRequestInfo;
  }>;
  rename(chatId: string, name: string): Promise<ActionResult>;
  /** 拉人入群（cmd=650，成功/失败名单在返回里回读） */
  addMembers(chatId: string, uids: string[]): Promise<ActionResult & {
    success?: string[];
    failed?: string[];
  }>;
  /** 移出群成员（cmd=651） */
  removeMembers(chatId: string, uids: string[]): Promise<ActionResult>;
  /** 退出群聊（cmd=652，响应为空 body） */
  leave(chatId: string): Promise<ActionResult>;
  /** 创建群聊（cmd=609），返回会话（含 chatId） */
  create(options: CreateGroupOptions): Promise<ActionResult & {
    group?: GroupInfo;
    chatId?: string;
  }>;
  /** 群分享校验：用邀请链接换群邀请凭证（ticket 可直接填入 groupCard.ticket 发卡） */
  verifyShare(input: GroupShareInput): Promise<GroupShareResult>;
}
//#endregion
//#region src/bot/chat.d.ts
declare class Chat {
  private readonly bot;
  constructor(bot: Bot);
  history(chatId: string, opts?: {
    cursor?: number;
    count?: number;
  }): Promise<ChatMessage[]>;
  strangers(): Promise<StrangerInfo[]>;
  /** 会话列表（旧 Cookie 通道，保留备用） */
  list(options?: {
    cursor?: number;
    count?: number;
  }): Promise<GroupInfo[]>;
  /** 会话详情（ticket/未读/成员），映射对齐列表会话 */
  info(chatId: string): Promise<GroupInfo[]>;
  /** 会话成员已读游标（cmd=2000） */
  readIndex(chatId: string): Promise<ReadIndexRow[]>;
  /** 会话成员最小同步游标（cmd=2001，增量拉取起点） */
  minIndex(chatId: string): Promise<MinIndexRow[]>;
  /** 按 uid 消息区间查询（cmd=12048，语义不完整返回原始结构） */
  userMessageStat(req?: UserMessageQuery): Promise<Record<string, unknown>>;
  /** 消息回执确认（cmd=2010） */
  ack(chatId: string, serverMessageId: string): Promise<ActionResult>;
  /** 陌生人会话列表（服务端限流 409 时 statusMsg 会给出原因） */
  strangerConversations(): Promise<ActionResult>;
  /** 将一批入站消息标记已读（会话侧收到 50013 已读回执的依据） */
  readSwitch(chatId: string, msgs: BotMessage[]): Promise<void>;
  /** 删除会话（cmd=603） */
  delete(chatId: string): Promise<ActionResult>;
  /** 会话设置：置顶/免打扰/收藏（cmd=921） */
  setting(chatId: string, input: ConversationSettingInput): Promise<ActionResult & {
    setting?: Record<string, unknown>;
  }>;
  /** 批量查所有成员已读游标（cmd=2038） */
  batchReadIndex(chatId: string): Promise<ActionResult>;
}
//#endregion
//#region src/bot/user.d.ts
declare class User {
  private readonly bot;
  constructor(bot: Bot);
  self(): Promise<SelfInfo>;
  /** passport 账号详情（uid/昵称/手机/邮箱，登录态） */
  account(): Promise<AccountInfo>;
  /** passport 令牌心跳（scene=boot 启动 / polling 周期轮询），续杯防掉线 */
  beatToken(scene?: string): Promise<void>;
  /** 批量查用户信息（昵称/头像/签名/关系），按 secUid */
  info(secUids: string[]): Promise<UserInfo[]>;
  /** 对话场景资料（字段比 profileOther 少） */
  profileScene(secUid: string): Promise<ProfileDetail>;
  /** 完整资料（含地域/年龄等原始字段，raw 透传） */
  profileOther(secUid: string): Promise<ProfileDetail>;
  /** 自己的完整资料 */
  profileSelf(): Promise<ProfileDetail>;
  /** 批量查 sec 用户在线状态 */
  onlineStatus(secUserIds: string[], source?: string): Promise<OnlineItem[]>;
  /** im 活跃心跳上报（登录后打一次即可） */
  heartbeat(): Promise<void>;
  /** 在线状态开关（1=开启，我可被对方看到在线） */
  activeSwitch(): Promise<number>;
}
//#endregion
//#region src/bot/sticker.d.ts
declare class Sticker$1 {
  private readonly bot;
  constructor(bot: Bot);
  /** 表情资源列表；scenes 缺省我的收藏，其他面板场景可自行传参探测 */
  list(options?: {
    scenes?: string;
    cursor?: number;
    limit?: number;
  }): Promise<StickerPage>;
  /** 我的收藏表情（CUSTOM_STICKER_PAGE 面板） */
  favs(): Promise<StickerPage>;
  /** 动图/GIF 表情：收藏中带 animate 动图的贴纸 */
  gifs(): Promise<StickerPage>;
  /** 收藏/取消收藏表情（remove=true 取消） */
  collect(ids: string[], options?: {
    remove?: boolean;
  }): Promise<StickerCollectResult>;
  /** 热门表情分页（cursor+count 翻页） */
  trending(options?: {
    cursor?: number;
    count?: number;
  }): Promise<StickerPage>;
  /** app 能力开关（决策树 + 动效资源包配置） */
  strategy(scenes?: string[]): Promise<StrategyConfig>;
  /** 图源 uri 渲染为打码图（分享卡片脱敏用），返回 CDN 直链列表 */
  privacyImage(uri: string, options?: {
    format?: string;
    tpl?: string;
  }): Promise<string[]>;
}
//#endregion
//#region src/bot/social.d.ts
declare class Social {
  private readonly bot;
  constructor(bot: Bot);
  /** 关注/好友关系列表（count+source 可调） */
  spotlight(options?: {
    count?: number;
    source?: string;
  }): Promise<RelationPage>;
  /** 可能认识的人 */
  familiar(options?: {
    count?: number;
    cursor?: number;
    recommendType?: number;
  }): Promise<SocialUser[]>;
  /** 关注用户（响应体为空，只判 HTTP 状态） */
  follow(userId: string, secUid: string, options?: {
    type?: number;
    tag?: string;
  }): Promise<void>;
  /** 气泡详情 */
  bubble(bubbleId: string, options?: {
    needCurrent?: boolean;
  }): Promise<Bubble[]>;
}
//#endregion
//#region src/bot/watch.d.ts
declare class Watch {
  private readonly bot;
  constructor(bot: Bot);
  /** 拉取作品弹幕（startTime/endTime 毫秒偏移窗口） */
  danmaku(itemId: string, options?: {
    groupId?: string;
    startTime?: number;
    endTime?: number;
    duration?: number;
    token?: string;
  }): Promise<Danmaku[]>;
  /** 上报播放进度 */
  progress(itemId: string, progress: number, duration: number): Promise<void>;
  /** 短剧剧集观看记录 */
  series(seriesId: string, itemId: string, episode: number): Promise<void>;
  /** 合集观看记录 */
  mix(mixId: string, itemId: string, episode: number): Promise<void>;
  /** 写入观看历史 */
  history(awemeId: string, options?: {
    authorId?: string;
    preItemId?: string;
  }): Promise<void>;
  /** 批量查作品安全等级 */
  safety(itemIds: string[]): Promise<Array<Record<string, unknown>>>;
}
//#endregion
//#region src/bot/notice.d.ts
declare class Notice$1 {
  private readonly bot;
  constructor(bot: Bot);
  /** 通知分组未读数（红点轮询用） */
  count(): Promise<NoticeCount[]>;
  /** 通知列表（缺省互动分组 401；markRead=false 拉取不标记已读） */
  list(options?: {
    count?: number;
    group?: number;
    maxTime?: number;
    minTime?: number;
    markRead?: boolean;
  }): Promise<NoticePage>;
}
//#endregion
//#region src/bot/setting.d.ts
declare class Setting {
  private readonly bot;
  constructor(bot: Bot);
  /** 桌面消息提醒设置 */
  desktop(): Promise<DesktopSetting>;
  /** 账号综合设置（私密等级/青少年模式，raw 透传全量字段） */
  account(): Promise<UserSettings>;
  /** 合规/青少年模式设置 */
  compliance(): Promise<ComplianceSetting>;
}
//#endregion
//#region src/app/auth.d.ts
declare class Auth {
  readonly jar: Jar;
  tokens: Record<string, string>;
  /** x-tt-passport-verify-portrait 每次会话随机 */
  portrait: string;
  traceId: string;
  lastHeaders: Record<string, string>;
  /** 2046 凭据：服务端靠它把「验证通过」关联到待登录会话 */
  mfaToken: string;
  /** 设备票据，响应头 d-ticket 下发 */
  dTicket: string;
  /** 本次 MFA 实际通过的验证方式（重放时 echo 到 std_verify_way） */
  verifiedWay: string;
  /** ticket-guard 短时票据：boot 响应头下发，业务请求缺它会被判未提供设备证明 */
  sec: string;
  secAt: number;
  /** odin_tt 有效期约 31s，按同样节奏刷新预热 */
  warmAt: number;
  constructor(cookie?: string);
  /** 真机 passport 会话的 csrf 由客户端自生成，每个 passport 请求都会带；缺了服务端按系统繁忙兜底 */
  private seed;
  cookie(): string;
  /** 二维码是独立会话：重新取码前清空上一轮 cookie/token，否则服务端按系统繁忙兜底 */
  reset(): void;
  absorb(setCookie: string[]): void;
  csrf(): string | undefined;
  get sessionid(): string | undefined;
  take(headers: Record<string, string>): void;
}
//#endregion
//#region src/app/keyhub.d.ts
interface ImSession {
  /** base64(DER ticket)，即 x-tt-e-t */
  ticket: string;
  ticketLong?: string;
  /** IM 通道 key（32B） */
  keyIM: Buffer;
  /** 普通 API 通道 key（32B） */
  keyAPI: Buffer;
  issuedAt: number;
  expiresAt: number;
  deviceId: string;
}
//#endregion
//#region src/app/im.d.ts
type Enc = 'pb' | 'json' | 'form' | 'zstd-json' | 'zstd-form' | 'none';
/**
 * path 以真机抓包为准：会话/消息/已读三个 pb 接口不带 /aweme 前缀，
 * enter_chat 与 active/status 带尾斜杠；前缀不对会命中网关兜底路由（200 空 body / 3105）。
 */
declare const IM_ENDPOINTS: {
  readonly conversationInfo: {
    readonly path: '/v2/conversation/get_info';
    readonly method: 'POST';
    readonly enc: 'pb';
  };
  readonly conversationInfoList: {
    readonly path: '/v2/conversation/get_info_list';
    readonly method: 'POST';
    readonly enc: 'pb';
    readonly host: 'api5-social-m-lf.amemv.com';
  };
  readonly markRead: {
    readonly path: '/v3/conversation/mark_read';
    readonly method: 'POST';
    readonly enc: 'pb';
  };
  readonly getByConversation: {
    readonly path: '/v1/message/get_by_conversation';
    readonly method: 'POST';
    readonly enc: 'pb';
  };
  readonly userMessage: {
    readonly path: '/v3/message/get_user_message';
    readonly method: 'POST';
    readonly enc: 'pb';
  };
  readonly enterChat: {
    readonly path: '/aweme/v1/im/service/enter_chat/';
    readonly method: 'POST';
    readonly enc: 'zstd-json';
  };
  readonly activeStatus: {
    readonly path: '/aweme/v1/im/user/active/status/';
    readonly method: 'POST';
    readonly enc: 'form';
  };
  readonly groupOnline: {
    readonly path: '/aweme/v1/im/user/group/online';
    readonly method: 'GET';
    readonly enc: 'none';
  };
  readonly bulletEvent: {
    readonly path: '/aweme/v1/im/bullet/common_event/request_and_update';
    readonly method: 'POST';
    readonly enc: 'json';
  };
  readonly groupEntryLimit: {
    readonly path: '/aweme/v1/im/group/settings/entry_limit';
    readonly method: 'GET';
    readonly enc: 'none';
  };
  readonly otherScene: {
    readonly path: '/aweme/v2/im/conversation/info/other/scene';
    readonly method: 'GET';
    readonly enc: 'none';
  };
  readonly otherInfo: {
    readonly path: '/aweme/v1/im/conversation/info/other';
    readonly method: 'POST';
    readonly enc: 'form';
  };
  readonly floatingBarCheck: {
    readonly path: '/aweme/v1/im/conversation/floating_bar/check';
    readonly method: 'GET';
    readonly enc: 'none';
  };
  readonly floatingBarConfigs: {
    readonly path: '/aweme/v1/im/conversation/floating_bar/configs';
    readonly method: 'GET';
    readonly enc: 'none';
  };
  readonly emoticonSearch: {
    readonly path: '/aweme/v1/im/resources/emoticon/search';
    readonly method: 'GET';
    readonly enc: 'none';
  };
  readonly hellosticker: {
    readonly path: '/aweme/v1/im/hellosticker';
    readonly method: 'GET';
    readonly enc: 'none';
  };
  readonly imageUpload: {
    readonly path: '/aweme/v1/im/image/upload';
    readonly method: 'POST';
    readonly enc: 'pb';
  };
};
type ImName = keyof typeof IM_ENDPOINTS;
interface Call {
  name?: ImName;
  /** 覆盖/自定义路径 */
  path?: string;
  /** 覆盖端点 host（业务接口分散在 core/platform/normal 等域） */
  host?: string;
  method?: 'GET' | 'POST';
  /** 覆盖端点编码 */
  enc?: Enc;
  body?: Buffer | string;
  query?: Record<string, string | number>;
  headers?: Record<string, string>;
  /** pb body 是否加密，默认 true */
  encrypt?: boolean;
  /** 复用 keyhub 会话 */
  session?: ImSession;
  timeoutMs?: number;
}
interface ImRes {
  status: number;
  headers: Record<string, string>;
  raw: Buffer;
  text: string;
  json?: unknown;
  /** 响应体可直接解析：加密响应已解开，或服务端本就返回明文 */
  ready: boolean;
}
//#endregion
//#region src/app/ee.d.ts
interface EeEntry {
  id: string;
  type?: number;
  /** 96B key 包 base64 */
  key: string;
  /** x-tt-e-t */
  ticket?: string;
  /** 秒 */
  expire?: number;
  r_exp?: number;
}
//#endregion
//#region src/app/http.d.ts
interface Res {
  status: number;
  /** 头名统一小写；同名合并为逗号串 */
  headers: Record<string, string>;
  setCookie: string[];
  body: Buffer;
  text: string;
  json: unknown;
}
//#endregion
//#region src/app/captcha.d.ts
interface Challenge {
  /** passport 会话票据，重试时回带 */
  verifyTicket: string;
  /** bdturing 决策（含加密 detail，只有 App SDK 能解） */
  decision: Record<string, unknown>;
  /** bdturing-verify 原文：外部验证页必须用它复刻本次决策，重新取会错位 */
  raw: string;
  /** x-vc-bdturing-parameters：bdturing 采集参数 */
  params: string;
  subtype: string;
  verifyEvent: string;
  logId: string;
  at: number;
}
//#endregion
//#region src/app/slide.d.ts
interface SlideOpts {
  /** 监听端口，默认 8787 */
  port?: number;
  /** 等待拖动的最长时间，默认 5 分钟 */
  timeoutMs?: number;
  /** 页面地址回调（默认只打印到日志）；需自定义二维码时可在这里处理 */
  onUrl?: (url: string) => void | Promise<void>;
}
/** 一次验证的结果：ok 通过；fail 拖错；cool 5014；timeout 用户没拖；closed 被关闭 */
type Result = 'ok' | 'fail' | 'cool' | 'timeout' | 'closed';
interface Slide {
  /** 手机扫码/输入打开的地址 */
  readonly url: string;
  readonly port: number;
  /** 已转发请求，便于排查 */
  readonly hits: string[];
  /** 通过为 true；失败/超时/关闭为 false */
  wait(): Promise<boolean>;
  /** 结束原因：失败后上层要据此决定是否重新向服务端取决策 */
  result(): Result;
  close(): void;
}
//#endregion
//#region src/app/conv.d.ts
interface ConvId {
  conversationId?: string;
  /** int64 用字符串传，避免超过 2^53 精度丢失 */
  shortId?: string | number;
  type?: number;
}
interface ConvPage {
  type?: number;
  cursor?: string | number;
  sort?: number;
  limit?: number;
}
interface HistoryOpts extends ConvId {
  direction?: number;
  anchor?: string | number;
  limit?: number;
}
interface ReadOpts extends ConvId {
  readIndex?: string | number;
  readIndexV2?: string | number;
  unread?: string | number;
  totalUnread?: string | number;
  badge?: number;
  ticket?: string;
}
interface UserMsgOpts {
  /** 会话增量版本，首帧传 0 */
  version?: string | number;
  cmdIndex?: string | number;
  strangerVersion?: string | number;
  readVersion?: string | number;
  source?: string;
  consultVersion?: string | number;
  notifyVersion?: string | number;
  threadVersion?: string | number;
  threadReadVersion?: string | number;
  needReadInfo?: boolean;
  /** 控制类消息链路游标，由上一次响应回传 */
  chainIndex?: string | number;
}
interface SendOpts extends ConvId {
  /** 统一消息体，给定时自动推导 messageType 与 content */
  body?: MsgBody;
  /** 纯文本或 JSON 内容，按 messageType 解释 */
  content?: string;
  ext?: Record<string, string>;
  messageType?: number;
  clientMessageId?: string;
  mentionedUsers?: Array<string | number>;
  threadId?: string;
  /** 引用回复 */
  ref?: {
    id?: string | number;
    hint?: string;
    rootId?: string | number;
    rootIndex?: string | number;
  };
}
interface CreateOpts {
  type?: number;
  users?: Array<string | number>;
  /** 单聊不生效，群聊名称 */
  name?: string;
  avatar?: string;
  desc?: string;
  bizExt?: Record<string, string>;
  ext?: Record<string, string>;
  idempotentId?: string;
  persistent?: boolean;
}
interface AuditOpts {
  cursor?: string | number;
  limit?: number;
  shortId?: string | number;
  /** 不清理未读 */
  keepUnread?: boolean;
}
interface StrangerOpts {
  cursor?: string | number;
  source?: number;
  scene?: number;
}
interface RecentStrangerOpts {
  latest?: string | number;
  earliest?: string | number;
  source?: string;
  newUser?: number;
  bizInfo?: string;
}
interface MemberOpts extends ConvId {
  cursor?: string | number;
  limit?: number;
}
interface MarkOpts extends ConvId {
  cursor?: string | number;
  limit?: number;
  asc?: boolean;
  actionType?: number;
  tag?: string | number;
  clearUnread?: boolean;
}
interface CmdOpts {
  /** 控制类消息版本游标 */
  version?: string | number;
  reverse?: boolean;
  source?: string;
}
interface RangeOpts extends ConvId {
  /** 会话内 v2 索引区间，闭区间 */
  min?: string | number;
  max?: string | number;
  direction?: number;
}
interface InitOpts {
  version?: string | number;
  page?: number;
}
interface ThreadOpts {
  threadVersion?: string | number;
  /** 一次取多少条盖楼会话 */
  threadLimit?: number;
  /** 每个盖楼取多少条消息 */
  msgLimit?: number;
}
interface TimeOpts {
  shortId?: string | number;
  earliest?: string | number;
  cursor?: string | number;
  limit?: number;
}
interface CmdRangeOpts {
  cmdIndex?: string | number;
  size?: number;
  direction?: number;
  chainIndex?: string | number;
}
interface SpecifiedOpts {
  shortId?: string | number;
  listType?: number;
  offset?: string | number;
  count?: number;
}
interface MsgMarkOpts extends ConvId {
  messageId: string | number;
  action?: number;
  actionType?: number;
  sortTime?: string | number;
  tag?: string | number;
}
interface ExtOpts extends ConvId {
  messageId: string | number;
  ext?: Record<string, string>;
  isEdited?: boolean;
  content?: string;
  messageType?: number;
  ticket?: string;
}
interface DelOpts extends ConvId {
  index?: string | number;
  indexV2?: string | number;
  badge?: number;
}
interface ThreadSubOpts {
  threadId?: string;
  threadShortId?: string | number;
  status: number;
}
interface ReactOpts extends ConvId {
  messageId: string | number;
  /** 表情键值，如 [爱心] */
  emoji: string;
  /** 默认添加回应，false 取消 */
  enabled?: boolean;
}
//#endregion
//#region src/app/friend.d.ts
interface ApplyOpts {
  /** 0 待处理 / 1 已通过 / 2 已拒绝 */
  status?: number;
  cursor?: string | number;
  limit?: number;
}
//#endregion
//#region src/app/app.d.ts
interface MfaAsk {
  way: string;
  kind: 'sms' | 'password' | 'up-sms' | 'qr';
  /** 掩码手机号 */
  mobile?: string;
  /** 上行短信内容让用户发到该号码 */
  sms?: {
    content: string;
    mobile?: string;
  };
  qr?: {
    url: string;
    base64?: string;
  };
}
interface VerifyOpts {
  /** 1105 滑块：把挑战交给调用方，回填 ticket 后重试 */
  onCaptcha?: (c: Challenge) => CaptchaCredential | Promise<CaptchaCredential>;
  /** 1105 滑块：起本地验证页让手机拖动，通过后自动回填票据重发；传对象可改端口/超时 */
  slide?: boolean | SlideOpts;
  /** 已输入的密码：2046 要求密码验证时直接复用，不再重复询问 */
  password?: string;
  /** 二次验证：返回短信验证码 / 密码；返回空串表示重发短信 */
  onMfa?: (m: MfaAsk) => string | Promise<string>;
  /** 二次验证方式选择：返回 verify_way 或下标；未提供时按内置优先级自动选 */
  onWay?: (ways: VerifyWay[]) => string | number | Promise<string | number>;
  /** MFA 扫码图 */
  onQr?: (qr: {
    url: string;
    base64?: string;
  }) => void | Promise<void>;
  /** 扫码状态变化：status + error_code */
  onStatus?: (s: string, code: number) => void | Promise<void>;
}
interface SmsOpts extends VerifyOpts {
  mobile: string;
  /** 直接给验证码；或用 onCode 在发码成功后再询问 */
  code?: string;
  onCode?: () => string | Promise<string>;
}
interface PwdOpts extends VerifyOpts {
  mobile: string;
  password: string;
}
interface CodeRes {
  sent: boolean;
  data: LoginData;
  /** 1105 滑块挑战 */
  captcha?: Challenge;
}
interface LoginRes {
  ok: boolean;
  userId: string;
  cookie: string;
  ids: Ids;
  data: LoginData;
  /** 未提供 onMfa 时返回服务端可用的二次验证方式 */
  ways?: VerifyWay[];
}
interface DeviceOpts {
  /** true 时丢弃已有 device_id 重新注册 */
  force?: boolean;
  host?: string;
}
declare class App {
  readonly dev: Dev;
  readonly ids: Ids;
  readonly auth: Auth;
  readonly log: Log;
  private flow?;
  private agent?;
  private convBot?;
  private accountBot?;
  private noticeBot?;
  private friendBot?;
  private resourceBot?;
  private socialBot?;
  private groupBot?;
  private configBot?;
  private growthBot?;
  private chatAiBot?;
  private commBot?;
  private mediaBot?;
  private sendBot?;
  private recvBot?;
  constructor(opts?: AppOpts);
  /** 注册并激活新设备（结果由调用方持久化后回传） */
  device(opts?: DeviceOpts): Promise<Ids>;
  /** 仅发送验证码；1105 时返回 captcha 交给调用方处理 */
  code(mobile: string, cred?: CaptchaCredential): Promise<CodeRes>;
  /** 为当前 1105 挑战起本地验证页；手机扫码拖动通过后 wait() 完成，再回填票据重发 */
  slide(opts?: SlideOpts): Promise<Slide>;
  /** 验证码登录（含 1105 重试与 2046 二次验证） */
  sms(opts: SmsOpts): Promise<LoginRes>;
  /** 密码登录（含 1105 重试与 2046 二次验证） */
  pwd(opts: PwdOpts): Promise<LoginRes>;
  /** 扫码登录（含二次验证：验证完成后重放 check_qrconnect） */
  qr(opts?: VerifyOpts): Promise<LoginRes>;
  /** 手动提交二次验证（未给 onMfa 回调时使用）：kind=sms/password/upsms */
  mfa(kind: 'sms' | 'password' | 'upsms' | 'qr', input?: string): Promise<LoginRes>;
  /** 账号信息（需已登录 Cookie） */
  info(): Promise<LoginData>;
  /** 当前登录态 */
  token(): {
    cookie: string;
    userId?: string;
  };
  /** 订阅 App 推送事件：事件名与 bot.on 一致，来源是 App Frontier 长连接 */
  on<K extends keyof ImEventMap>(event: K, fn: (...args: ImEventMap[K]) => void): void;
  /** 建立 App Frontier 长连接（需已登录，握手带 X-Tt-Token） */
  start(): Promise<void>;
  stop(): void;
  get connected(): boolean;
  /** 关闭/开启「保存登录信息」 */
  record(status: 1 | 2): Promise<LoginData>;
  /** keyhub 握手结果（IM 加密密钥） */
  key(): Promise<{
    ticket: string;
    key: string;
    expiresAt: number;
  }>;
  /** 调用 IM 接口（默认按端点表加密 pb） */
  im(call?: Call): Promise<ImRes>;
  /** 导出 ee.info 96B key 包，供外部进程复用 IM 会话 */
  ee(id?: string): Promise<EeEntry>;
  /** 会话列表（pb cmd=2006） */
  convList(opts?: ConvPage): Promise<Record<string, unknown>>;
  /** 批量会话详情（pb cmd=610） */
  convInfos(list: ConvId[]): Promise<Record<string, unknown>>;
  /** 单个会话详情（pb cmd=608） */
  convInfo(id: ConvId): Promise<Record<string, unknown>>;
  /** 历史消息（pb cmd=301） */
  history(opts: HistoryOpts): Promise<Record<string, unknown>>;
  /** 标记已读（pb cmd=2002） */
  read(opts: ReadOpts): Promise<Record<string, unknown>>;
  /** 成员已读游标（pb cmd=2000） */
  readIndex(id: ConvId): Promise<Record<string, unknown>>;
  /** 最小同步游标（pb cmd=2001） */
  minIndex(id: ConvId): Promise<Record<string, unknown>>;
  /** 消息索引统计（pb cmd=12048） */
  userMessage(opts?: UserMsgOpts): Promise<Record<string, unknown>>;
  /** 发送消息（pb cmd=100）；媒体输入源自动上传，forward 走 App 域注册 */
  send(opts: SendOpts): Promise<Record<string, unknown>>;
  /** 表情回应（pb cmd=705）；emoji 传键值如 [爱心]，false 取消 */
  react(opts: ReactOpts): Promise<Record<string, unknown>>;
  /** 创建会话（pb cmd=609） */
  createConv(opts: CreateOpts): Promise<Record<string, unknown>>;
  /** 陌生人会话列表（pb cmd=1001） */
  strangerList(opts?: StrangerOpts): Promise<Record<string, unknown>>;
  /** 会话审核列表（pb cmd=2027） */
  auditList(opts?: AuditOpts): Promise<Record<string, unknown>>;
  /** 批量查成员已读游标（pb cmd=2038） */
  participantsReadIndex(id: ConvId): Promise<Record<string, unknown>>;
  /** 最近陌生人消息（pb cmd=12047） */
  recentStranger(opts?: RecentStrangerOpts): Promise<Record<string, unknown>>;
  /** 会话参与者分页（pb cmd=605） */
  participants(opts?: MemberOpts): Promise<Record<string, unknown>>;
  /** 会话成员列表（pb cmd=12060） */
  members(opts?: MemberOpts): Promise<Record<string, unknown>>;
  /** 批量取多个会话成员（pb cmd=12061） */
  membersBatch(list: MemberOpts[]): Promise<Record<string, unknown>>;
  /** 按 uid 精确取成员（pb cmd=654） */
  membersByUid(id: ConvId, users: Array<string | number>): Promise<Record<string, unknown>>;
  /** 按标记位增量拉消息（pb cmd=2037） */
  marks(opts?: MarkOpts): Promise<Record<string, unknown>>;
  /** 最近控制类消息会话（pb cmd=12062） */
  cmds(opts?: CmdOpts): Promise<Record<string, unknown>>;
  /** 会话内控制类消息（pb cmd=2040） */
  cmdMessages(opts?: CmdOpts): Promise<Record<string, unknown>>;
  /** 会话内 v2 索引区间消息（pb cmd=2041） */
  msgRange(opts: RangeOpts): Promise<Record<string, unknown>>;
  /** 冷启动首屏消息（pb cmd=2043） */
  msgInit(opts?: InitOpts): Promise<Record<string, unknown>>;
  /** 盖楼消息冷启动（pb cmd=2204） */
  threadInit(opts?: ThreadOpts): Promise<Record<string, unknown>>;
  /** 按服务端消息 id 取单条（pb cmd=211） */
  msg(id: ConvId, messageId: string | number, onlyStatus?: boolean): Promise<Record<string, unknown>>;
  /** 按服务端消息 id 批量取（pb cmd=212） */
  msgs(id: ConvId, messageIds: Array<string | number>): Promise<Record<string, unknown>>;
  /** 按时间翻页取消息（pb cmd=310） */
  byTime(opts?: TimeOpts): Promise<Record<string, unknown>>;
  /** 消息标记/取消标记（pb cmd=2036） */
  mark(opts: MsgMarkOpts): Promise<Record<string, unknown>>;
  /** 修改消息扩展与内容（pb cmd=2021） */
  modifyExt(opts: ExtOpts): Promise<Record<string, unknown>>;
  /** 控制类消息区间（pb cmd=12040） */
  cmdRange(opts?: CmdRangeOpts): Promise<Record<string, unknown>>;
  /** 指定类型消息列表（pb cmd=12050） */
  specified(opts: SpecifiedOpts): Promise<Record<string, unknown>>;
  /** 收藏会话列表（pb cmd=611） */
  favorite(opts?: {
    cursor?: string | number;
    limit?: number;
  }): Promise<Record<string, unknown>>;
  /** 置顶会话列表（pb cmd=612） */
  top(opts?: {
    cursor?: string | number;
    limit?: number;
    type?: number;
  }): Promise<Record<string, unknown>>;
  /** 批量标记已读（pb cmd=613） */
  batchRead(list: ReadOpts[]): Promise<Record<string, unknown>>;
  /** 批量删除会话（pb cmd=619） */
  batchDelete(list: DelOpts[]): Promise<Record<string, unknown>>;
  /** 清空会话消息（pb cmd=620） */
  clearMsg(opts: DelOpts): Promise<Record<string, unknown>>;
  /** 最近陌生人会话（pb cmd=12063） */
  recentStrangerConv(opts?: {
    max?: string | number;
    min?: string | number;
    reverse?: boolean;
    source?: string;
  }): Promise<Record<string, unknown>>;
  /** 盖楼订阅状态（pb cmd=2205） */
  threadSub(opts: ThreadSubOpts): Promise<Record<string, unknown>>;
  /** 本人主页 */
  self(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 他人主页（sec_user_id） */
  other(secUserId: string, query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 主页场景配置 */
  scene(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 个人设置 */
  userSettings(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 全局设置 */
  settings(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 社交关系设置 */
  socialSettings(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 社交计数（zstd-form） */
  socialCount(body: string): Promise<Record<string, unknown>>;
  /** 合规设置 */
  compliance(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 封禁信息 */
  ban(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 紧急禁用状态 */
  forbid(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** DX 状态 */
  dx(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 资料同步提示 */
  syncTips(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 隐私图片 */
  privacyImage(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 通知未读数 */
  noticeCount(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 通知列表 */
  noticeList(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 好友推荐 */
  recommend(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 推荐候选 topK */
  topk(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 新推荐用户数量 */
  recommendCount(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 收到的好友申请（pb cmd=2048） */
  applies(opts?: ApplyOpts): Promise<Record<string, unknown>>;
  /** 熟人视频访客列表 */
  visitors(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 熟人视频统计上报 */
  videoStats(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** VoIP 冷启动拉取 */
  voipColdPull(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 收藏的用户列表 */
  collectUsers(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 审批好友申请（pb cmd=2049） */
  replyFriend(uids: Array<string | number>, attitude: 1 | 2): Promise<Record<string, unknown>>;
  /** 资源位聚合 */
  resources(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 表情资源 */
  emoji(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 表情搜索 */
  emoticon(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 打招呼贴纸 */
  helloSticker(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 上传通道配置 */
  uploadConfig(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 收藏文件 */
  collectFile(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 好友相册列表 */
  album(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 批量加入好友相册 */
  albumAdd(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 关注关系推荐 */
  spotlight(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 熟人设置 */
  familiar(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 用户推荐 */
  userRecommend(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 本地通讯录用户 */
  localUsers(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 用户中心聚合 */
  center(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 用户中心计划 */
  centerPlan(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 用户中心同步 */
  centerSync(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 用户中心消息同步 */
  centerMsgs(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 我加入的群列表 */
  groups(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群指标 */
  indicators(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 区间群聊链条 */
  chains(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 按群 id 取链条 */
  chain(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群打卡信息 */
  checkin(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群打卡权限校验 */
  checkinAuth(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 成员设置更新 */
  memberSettings(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群操作扫描 */
  groupScan(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群标签扫描 */
  groupTags(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群活跃信息 */
  active(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群活跃信息扫描 */
  activeScan(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群号 */
  groupNumber(shortId: string | number): Promise<Record<string, unknown>>;
  /** 群资料更新 */
  updateGroup(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群可见范围 */
  visible(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群合照样式 */
  mixPhoto(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群资料校验 */
  validate(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群升级信息 */
  upgrade(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群升级信息列表 */
  upgrades(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 会话悬浮条是否展示 */
  floatingCheck(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 会话悬浮条配置 */
  floatingConfigs(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 默认聊天背景图 */
  backgrounds(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 会话场景信息 */
  convScene(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 会话附加信息 */
  convOther(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 会话可打开应用列表 */
  openApps(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 推荐折叠群 */
  foldGroups(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群任务列表 */
  groupTasks(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群任务更新 */
  groupTaskUpdate(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群操作批量校验 */
  groupMultiCheck(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 入群门槛设置 */
  entryLimit(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群聊词库设置 */
  groupWords(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 群广场热点 */
  groupHotspot(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群广场推荐 */
  groupRecommend(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群广场信息 */
  groupSquare(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群广场搜索 */
  groupSearch(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 群操作前置校验 */
  groupActionCheck(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 按群 id 批量取群 */
  groupOthers(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 建群面板信息 */
  groupPanel(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 可邀请的粉丝列表 */
  groupFansList(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 粉丝群卡片状态 */
  groupFansCard(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 客户端 IM 配置 */
  imConfig(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 服务端全局配置 */
  globalConfig(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 策略配置 */
  strategyConfig(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 重启降级配置 */
  rebootConfig(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 用户活跃配置 */
  activeConfig(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 用户活跃心跳更新 */
  activeUpdate(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 上报用户活跃状态 */
  activeStatus(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 进入会话上报 */
  enterChat(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 进入消息 Tab 上报 */
  msgTabEnter(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 连续聊天关系成就 */
  consecutive(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 成长分享列表 */
  growthShare(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 连续聊天开关 */
  consecutiveSwitch(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 连续聊天上报 */
  consecutiveReport(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 动态策略 */
  growthDynamic(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 语音识别模型配置 */
  audioModel(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 火焰成就 */
  flame(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** Gaga 聚合信息 */
  gaga(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 宠物聚合信息 */
  pet(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 宠物精灵邀请卡 */
  petCard(query?: Record<string, string | number>): Promise<Record<string, unknown>>;
  /** 子弹事件请求并更新 */
  bullet(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 子弹事件数据提交 */
  bulletSubmit(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 实验命中查询 */
  expHit(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 合并消息卡准备 */
  mergePrepare(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 通信杂项上报 */
  commMisc(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  /** 分享上报 */
  shareReport(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  private get conv();
  private get account();
  private get notice();
  private get friend();
  private get resource();
  private get social();
  private get group();
  private get config();
  private get growth();
  private get chatAi();
  private get comm();
  private get media();
  private get sender();
  private get recv();
  private get login();
  private begin;
  private agentOf;
  /**
   * 1105 滑块：回调换 ticket 后重试；没给回调但开了 slide 就起本地验证页并自动续跑。
   * 真机 HAR 实测同一 detail 在 500 后可重新 get 新题再验（native SDK 行为），
   * 因此页面内换题由 slide 自己完成；本层只在决策整体失效时重发登录取新决策。
   */
  private retry;
  /** 2046 二次验证：按优先级尝试，全部完成后重放原请求 */
  private finish;
  /** 处理一轮验证；返回 false 表示没有可用方式/用户取消 */
  private verifyOnce;
  /** 选验证方式：交给调用方交互选择，缺省按内置优先级兜底 */
  private wayOf;
  /** 登录收尾：update_token → 保存登录信息 → 账号信息 */
  private after;
  private res;
}
//#endregion
//#region src/bot/bot.d.ts
declare class Bot extends Emitter<BotEventMap> {
  readonly msg: Msg;
  readonly media: Media;
  readonly frd: Frd;
  readonly grp: Grp;
  readonly chat: Chat;
  readonly user: User;
  readonly sticker: Sticker$1;
  readonly social: Social;
  readonly watch: Watch;
  readonly notice: Notice$1;
  readonly setting: Setting;
  readonly app: App;
  private readonly opts;
  private readonly log;
  private readonly nicks;
  private userId;
  private core?;
  private receiver?;
  constructor(opts: BotOpts);
  /** 自身数字 uid（start 后可用） */
  get id(): string;
  /** 当前设备身份（start 后可用）；持久化后下次构造用 opts.device 注入，避免重复注册 */
  get device(): Device | undefined;
  start(): Promise<void>;
  stop(): void;
  /** 域方法内部取用；未启动即抛出 */
  ctx(): Ctx;
  http(): Http;
  rememberNicks(entries: readonly {
    uid: string;
    nickname?: string;
    alias?: string;
  }[]): void;
  /** 按 uid 查昵称：TTL 内命中直接返回；未命中拉一次好友列表整体回填（发送 @ 自动补昵称用） */
  nickOf(uid: string): Promise<string | undefined>;
  /** 发送者昵称补拉：同 uid 并发去重；失败静默不影响下发 */
  private ensureNick;
  private fetchNick;
  /** 把接收层推送接到 Bot 事件层：message 类补 chatId 与昵称，其余原样透传 */
  private wire;
  /** 等昵称与视频地址补拉完成再下发，首条消息即带完整字段 */
  private forward;
  /** 视频播放地址补拉：随事件直接下发，失败静默（调用方仍可 media.videoUrl 手动换） */
  private ensureVideoUrl;
}
//#endregion
//#region src/bot/address.d.ts
/** chatId：`type:shortId:conversationId` 的不透明串，格式不承诺稳定 */
declare function chatIdOf(src: PushMessage | {
  conversationId: string;
  conversationShortId: string;
  conversationType: number;
}): string;
//#endregion
//#region src/session/login/types.d.ts
type QrStatus = 'new' | 'scanned' | 'confirmed' | 'expired' | (string & {});
interface QrUserData {
  app_id?: number;
  user_id?: number;
  user_id_str?: string;
  sec_user_id?: string;
  screen_name?: string;
  name?: string;
  avatar_url?: string;
  mobile?: string;
  has_password?: number;
  country_code?: number;
  [key: string]: unknown;
}
/** 服务端可选的二次验证方式(assist_ 前缀 = 安全手机) */
interface VerifyWay$1 {
  verify_way?: string;
  mobile?: string;
  sms_content?: string;
  channel_mobile?: string;
  [key: string]: unknown;
}
/** 二次验证输入描述:kind=sms 附 maskedMobile,kind=password 需返回账号密码 */
interface MfaInfo {
  kind?: 'sms' | 'password';
  maskedMobile?: string;
}
interface LoginOpts {
  /** 取码后回调:QR 串(扫码页 URL,兜底 token)与 base64 图,渲染权交给调用方 */
  onQr?: (qr: {
    url: string;
    base64?: string;
  }) => void | Promise<void>;
  /** 扫码状态:new/scanned/verifying/confirmed…(含中文提示文案) */
  onStatus?: (s: string) => void | Promise<void>;
  /** 需本地安全验证时回调:验证页地址(浏览器打开) */
  onVerifyUrl?: (url: string) => void;
  /** 触发二次验证时回调:返回短信验证码或密码;未提供则登录失败 */
  onMfa?: (info: MfaInfo) => string | Promise<string>;
  /**
   * 二次验证方式拉取:触发时回调服务端全部可用方式,返回要使用的 verify_way 名称;
   * 返回 undefined 走内置优先级(安全手机短信 > 绑定手机短信 > 上行短信 > 密码)
   */
  onVerifyWays?: (ways: VerifyWay$1[]) => string | undefined | Promise<string | undefined>;
  userAgent?: string;
  /**
   * 已持久化的设备身份；注入后跳过注册（沿用同一设备登录，避免每次登录触发 MFA）。
   * 省略时注册新设备并通过 `session.device` 返回。
   */
  device?: Device;
  log?: Log;
}
/** 登录会话:userId 为数字 uid(frontier 握手/消息过滤需要),存储由调用方自理 */
interface Session {
  userId: string;
  cookie: string;
  userData?: QrUserData;
  /** 本次登录使用的设备身份;落盘后可在下次 login / new Bot 注入复用 */
  device?: Device;
}
//#endregion
//#region src/session/login/login.d.ts
/** 扫码登录全流程;调用链形态对齐 douyin-im beginLogin 桌面流程 */
declare function login(opts?: LoginOpts): Promise<Session>;
//#endregion
//#region src/media/cenc.d.ts
/**
 * 解密 CENC(cenc 方案) 加密 mp4：keyHex 为消息 `video.skey`（32 hex = 16 字节 AES-128）。
 * 输出可直接播放的 mp4；未加密的输入原样返回。
 */
declare function decryptCencMp4(data: Uint8Array, keyHex: string): Buffer;
//#endregion
//#region src/session/log.d.ts
/** quiet 整体关停输出；tag 区分多实例来源 */
declare function createLog(opts?: {
  tag?: string;
  quiet?: boolean;
}): Log;
//#endregion
//#region src/error.d.ts
/**
 * SDK 只把错误来源原样交回，不做字段重命名、不拼描述、不映射错误码。
 * 上游失败 → data 是上游响应体；前置校验 → data 是失败字段；网络失败 → data 是原生错误。
 */
declare class SdkError<T = unknown> extends Error {
  readonly data: T;
  readonly name = "SdkError";
  constructor(data: T, options?: ErrorOptions);
}
declare function isErr(value: unknown): value is SdkError;
//#endregion
export { type AccountInfo, type ActionResult, App, type ImEvent as AppEvent, type ImEventMap as AppEventMap, type AppOpts, type VerifyWay as AppWay, type ApplyOpts, type AuditOpts, type AwemeDetail, Bot, type BotEvent, type BotEventMap, type BotMessage, type BotOpts, type Bubble, type CaptchaCredential, type Card, type Challenge, type ChatMessage, type ClientAckItem, type CodeRes, type ComplianceSetting, type ConvId, type ConvPage, type ConversationAddress, type CreateOpts, type Danmaku, type DesktopSetting, type Dev, type Device, type DeviceOpts, type EeEntry, type EmojiInfo, type EncryptedVideoUrl, type FileUploadAsset, type FriendInfo, type FriendRequestInfo, type GetPeerRequest, type GetPeerResult, type GroupCard, type GroupInfo, type GroupJoinRequestInfo, type GroupMemberChange, type GroupMemberInfo, type GroupMemberUpdate, type GroupShareInput, type GroupShareResult, type HistoryOpts, type Ids, type Call as ImCall, type ImName, type ImRes, type ImageAsset, type InboundMessage, type LinkCard, type LocationCard, type Log, type LoginData, type LoginOpts, type LoginRes, type MediaInput, type MfaAsk, type MfaCtx, type MfaInfo, type MinIndexRow, type MsgBody, type Notice, type NoticeCount, type NoticeEvent, type NoticePage, type OnlineItem, type ProfileDetail, type PwdOpts, type QrStatus, type ReactOpts, type ReadEvent, type ReadIndexRow, type ReadOpts, type ReadSwitchItem, type RecallResult, type RecentStrangerOpts, type RecvBody, type RelationPage, type RequestEvent, type Res, SdkError, type SendOpts, type Session, type ShareItem, type Slide, type SlideOpts, type SmsOpts, type SocialUser, type StatusEvent, type Sticker, type StickerCollectResult, type StickerImage, type StickerPage, type StrangerInfo, type StrangerListOptions, type StrangerOpts, type StrategyConfig, type TextMention, type UserCard, type UserMessageQuery, type UserMsgOpts, type UserProfile, type UserSettings, type VerifyOpts, type VerifyWay$1 as VerifyWay, type VideoAsset, type VideoSend, type VoipCallEvent, type WsCloseEvent, type WsReconnectEvent, chatIdOf, createLog, decryptCencMp4, isErr, login };