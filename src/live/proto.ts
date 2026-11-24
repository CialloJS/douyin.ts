import protobuf from 'protobufjs'

/**
 * 抖音 IM 协议 schema（等价迁移自 douyin-im src/services/im/proto/im.proto）。
 * tsdown 打包单文件时独立 .proto 不会被携带，因此内联为字符串常量，
 * 用 protobuf.parse（keepCase=false，与 protobuf.load 默认行为一致）解析。
 */
export const IM_PROTO_SOURCE = `
syntax = "proto3";
package im;

message RequestEnvelope {
  int32 cmd = 1;
  int64 sequence_id = 2;
  string sdk_version = 3;
  string token = 4;
  int32 refer = 5;
  int32 inbox_type = 6;
  string build_number = 7;
  RequestPayload body = 8;
  string device_id = 9;
  string channel = 10;
  string device_platform = 11;
  string device_type = 12;
  string os_version = 13;
  string version_code = 14;
  map<string, string> headers = 15;
  int32 config_id = 16;
  TokenInfo token_info = 17;
  int32 auth_type = 18;
  string biz = 21;
  string access = 22;
  string ts_sign = 23;
  string sdk_cert = 24;
  string reuqest_sign = 25;
}

message TokenInfo {
  int32 mark_id = 1;
  int32 type = 2;
  int32 app_id = 3;
  int64 user_id = 4;
  int64 timestamp = 5;
}

message RequestPayload {
  SendMessageRequest send_message = 100;
  InboxRequest inbox = 203;
  ConversationMessagesRequest conversation_messages = 301;
  SendUserActionRequest send_user_action = 410;
  SendInputStatusRequest send_input_status = 411;
  DeleteConversationRequest delete_conversation = 603;
  // Native rawMarkConversationRead uses outer cmd 2002 but keeps body oneof tag 604.
  MarkConversationReadRequest mark_conversation_read = 604;
  ConversationParticipantsListRequest conversation_participants = 605;
  GetConversationInfoV2Request get_conversation_info_v2 = 608;
  CreateConversationV2Request create_conversation_v2 = 609;
  GetConversationInfoListV2Request get_conversation_info_list_v2 = 610;
  DissolveConversationRequest dissolve_conversation = 614;
  ConversationAddParticipantsRequest conversation_add_participants = 650;
  ConversationRemoveParticipantsRequest conversation_remove_participants = 651;
  ConversationLeaveRequest leave_conversation = 652;
  ConversationSetRoleRequest conversation_set_role = 653;
  DeleteMessageRequest delete_message = 701;
  RecallMessageRequest recall_message = 702;
  ModifyMessagePropertyRequest modify_message_property = 705;
  SetConversationCoreInfoRequest set_conversation_core_info = 902;
  GetConversationSettingInfoRequest get_conversation_setting_info = 920;
  SetConversationSettingInfoRequest set_conversation_setting_info = 921;
  ConversationListRequest conversation_list = 2006;
  AckConversationApplyRequest ack_conversation_apply = 2025;
  GetConversationAuditListRequest get_conversation_audit_list = 2027;
  GetFriendReceiveApplyListRequest get_friend_receive_apply_list = 2048;
  ReplyFriendApplyRequest reply_friend_apply = 2049;
  GetRecentStrangerMessageReqBody get_recent_stranger_message = 12047;
  CreateVoipRequestBody create_voip = 2011;
  CallVoipRequestBody call_voip = 2012;
  // 以下对齐 native 客户端一并支持的查询/回执类接口：
  // stranger get_conversation_list 外层 cmd=1001、body oneof 独立占 tag=1000
  StrangerConversationListRequest stranger_conversation_list = 1000;
  GetReadIndexRequest get_read_index = 2000;
  GetMinIndexRequest get_min_index = 2001;
  ClientAckRequest client_ack = 2010;
  GetUserMessageRequest get_user_message = 12048;
  GetConversationParticipantsReadIndexRequest get_conversation_participants_read_index = 2038;
  MgetConversationParticipantsRequest mget_conversation_participants_body = 654;
  PullMarkMessageRequest pull_mark_message_body = 2037;
  GetCmdMessageRequest get_cmd_message_body = 2040;
  GetMessageRangeRequest get_message_info_by_index_v2_range_body = 2041;
  MessageByInitRequest message_by_init = 2043;
  ThreadMessageByInitRequest thread_message_by_init = 2204;
  GetMessageByIdRequest get_message_by_id_body = 211;
  GetMessagesByIdListRequest get_messages_by_server_id_list_body = 212;
  GetConversationMessagesByTimeRequest get_conversation_messages_by_time_body = 310;
  MarkMessageRequest mark_message_body = 2036;
  ModifyMessageExtRequest modify_message_ext_body = 2021;
  GetCmdMessageRangeRequest get_cmd_message_range_body = 12040;
  GetSpecifiedMessageListRequest get_conversation_specified_message_list_body = 12050;
  GetConversationInfoListByFavoriteRequest get_conversation_info_list_by_favorite_v2_body = 611;
  GetConversationInfoListByTopRequest get_conversation_info_list_by_top_v2_body = 612;
  BatchMarkConversationReadRequest batch_mark_read_body = 613;
  BatchDeleteConversationRequest batch_delete_conversation_body = 619;
  ClearConversationMessageRequest clear_conversation_message_v2_body = 620;
  GetConversationMemberListRequest get_conversation_member_list_body = 12060;
  BatchGetConversationMemberListRequest batch_get_conversation_member_list_body = 12061;
  GetRecentCmdConvRequest get_recent_cmd_conv = 12062;
  GetRecentStrangerConvRequest get_recent_stranger_conv = 12063;
  UpdateThreadSubscribeStatusRequest update_thread_subscribe_status = 2205;
}

message GetConversationInfoV2Request {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message GetConversationInfoListV2Request {
  repeated GetConversationInfoV2Request conversation_info_list = 1;
}

message GetConversationInfoV2Response {
  ConversationV2 conversation_info = 1;
}

message GetConversationInfoListV2Response {
  repeated ConversationV2 conversation_info_list = 1;
}

message SendUserActionRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int32 action_type = 4;
  map<string, string> extra = 5;
}

message SendInputStatusRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int32 status = 4;
  map<string, string> extra = 5;
}

message CreateVoipRequestBody {
  string idempotent_id = 1;
  // VoipType：1=ALL 2=VIDEOONLY 3=AUDIOONLY
  int32 v_type = 2;
  int64 con_short_id = 3;
  int64 srv_msg_id = 4;
  string ref_channel_id = 5;
  // VoipMode：0=DOUBLE 1=MULTIPLAYER
  int32 voip_mode = 6;
}

message CreateVoipResponseBody {
  VoipInfo info = 1;
  // VoipStatusCode：0=SUCCESS 4=PARAMS_ERROR 18=STATUS_ERROR ...
  int32 status_code = 2;
  int32 voip_mode = 3;
}

message CallVoipRequestBody {
  repeated int64 callee_ids = 1;
  string channel_id = 2;
  int32 v_type = 3;
  map<string, string> ext = 4;
  repeated int64 ref_channel_users = 5;
  string con_id = 6;
}

message CallVoipResponseBody {
  VoipInfo info = 1;
  repeated int64 callee_ids = 2;
  int32 status = 3;
  string extra_info = 4;
  int64 check_code = 5;
  string check_message = 6;
  string ref_channel_id = 7;
  int32 voip_mode = 8;
}

message VoipInfo {
  int64 user_id = 1;
  string device_id = 2;
  string channel_id = 3;
  string token = 4;
  // VoipStatus：1=CALLING 2=RINGING 3=ACCEPTED 4=ONTHECALL 101+=结束态
  int32 status = 5;
  int64 caller_id = 6;
  int64 created_time_ms = 7;
  int64 updated_time_ms = 8;
  int64 con_short_id = 9;
  int32 v_type = 10;
  int64 srv_msg_id = 11;
}

message DissolveConversationRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message ModifyPropertyContent {
  int32 operation = 1;
  string key = 2;
  string value = 3;
  string idempotent_id = 4;
}

message ModifyPropertyBody {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 server_message_id = 4;
  string client_message_id = 5;
  repeated ModifyPropertyContent modify_property_content = 6;
}

message ModifyMessagePropertyRequest {
  repeated ModifyPropertyBody property_list = 1;
  string ticket = 2;
}

message GetFriendReceiveApplyListRequest {
  int64 cursor = 1;
  int64 limit = 2;
  bool get_total_count = 3;
  int32 status = 4;
}

message ReplyFriendApplyRequest {
  repeated int64 user_id = 1;
  int32 attitude = 2;
  map<string, string> ext = 3;
}

message CreateConversationV2Request {
  int32 conversation_type = 1;
  repeated int64 participants = 2;
  bool persistent = 3;
  string idempotent_id = 4;
  string name = 6;
  string avatar_url = 7;
  string description = 8;
  map<string, string> biz_ext = 11;
  map<string, string> ext = 13;
}

message ConversationAddress {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message DeleteConversationRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_message_index = 4;
  int64 last_message_index_v2 = 5;
  int32 badge_count = 6;
}

message MarkConversationReadRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 read_message_index = 4;
  int64 conv_unread_count = 5;
  int64 total_unread_count = 6;
  int64 read_message_index_v2 = 7;
  int32 read_badge_count = 8;
  string ticket = 9;
  int64 server_message_id = 10;
}

message ConversationAddParticipantsRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  repeated int64 participants = 4;
  map<string, string> biz_ext = 5;
}

message ConversationParticipantsListRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 cursor = 4;
  int32 limit = 5;
}

message ConversationSetRoleRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  map<int64, int32> roles = 4;
}

message ConversationRemoveParticipantsRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  repeated int64 participants = 4;
  map<string, string> biz_ext = 5;
}

message ConversationLeaveRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message DeleteMessageRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 message_id = 4;
}

message SetConversationCoreInfoRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  string name = 4;
  string desc = 5;
  string icon = 6;
  string notice = 7;
  bool is_name_set = 8;
  bool is_desc_set = 9;
  bool is_icon_set = 10;
  bool is_notice_set = 11;
  map<string, string> ext = 12;
}

message SetConversationSettingInfoRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  bool set_stick_on_top = 4;
  bool set_mute = 5;
  bool set_favorite = 6;
}

message GetConversationSettingInfoRequest {
  int64 conversation_short_id = 2;
}

message ConversationListRequest {
  int32 list_type = 1;
  int64 cursor = 2;
  int32 sort_type = 3;
  int32 limit = 4;
}

message AckConversationApplyRequest {
  int64 apply_id = 1;
  int32 apply_status = 2;
  map<string, string> biz_ext = 3;
}

message GetConversationAuditListRequest {
  int64 cursor = 1;
  int32 limit = 2;
  int64 conv_short_id = 3;
  bool no_clear_unread = 4;
}

message RecallMessageRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 server_message_id = 4;
}

message InboxRequest {
  int64 cursor = 1;
  int32 new_user = 2;
  int32 init_sub_type = 3;
  int32 conv_limit = 4;
  int32 msg_limit = 5;
}

message SendMessageRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  string content = 4;
  map<string, string> ext = 5;
  int32 message_type = 6;
  string ticket = 7;
  string client_message_id = 8;
  repeated int64 mentioned_users = 9;
  // field 10：盖楼归属候选落点（type=50 三元组唯一空缺）；
  // 实测差分：int64(wire0) 与缺省同为 status=4（wire0 被忽略）；string(wire2) 首段纯数字为 -1（值被拒）→
  // 真实类型是 string，值应为 thread_id 全串（服务器唯一见过的 thread 标识：落地帧 f500.f2 / emoticon conv_id）
  string thread_id = 10;
  ReferencedMessageInfo ref_msg_info = 11;
}

message ReferencedMessageInfo {
  int64 referenced_message_id = 1;
  string hint = 2;
  int64 root_message_id = 3;
  int64 root_message_conv_index = 4;
}

message ConversationMessagesRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int32 direction = 4;
  int64 anchor_index = 5;
  int32 limit = 6;
}

message ResponseEnvelope {
  int32 cmd = 1;
  int64 sequence_id = 2;
  int32 status_code = 3;
  string error_desc = 4;
  int32 inbox_type = 5;
  ResponsePayload body = 6;
  string log_id = 7;
  map<string, string> headers = 8;
  int64 start_time_stamp = 9;
  int64 request_arrived_time = 10;
  int64 server_execution_end_time = 11;
  int64 user_id = 13;
}

message Frame {
  uint64 seqid = 1;
  uint64 logid = 2;
  int32 service = 3;
  int32 method = 4;
  repeated FrameHeaderEntry headers = 5;
  string payload_encoding = 6;
  string payload_type = 7;
  bytes payload = 8;
}

message FrameHeaderEntry {
  string key = 1;
  string value = 2;
}

message ResponsePayload {
  SendMessageResponse send_message = 100;
  InboxResponse inbox = 203;
  ConversationMessagesResponse conversation_messages = 301;
  NewMessageNotify has_new_message_notify = 500;
  MarkConversationReadNotify has_mark_read_notify = 501;
  ConversationInfoUpdatedNotify has_conversation_info_updated_notify = 502;
  NewP2PMessageNotify has_new_p2p_message_notify = 504;
  NewFriendMessageNotify new_friend_message_notify = 507;
  ConversationParticipantsListResponse conversation_participants = 605;
  GetConversationInfoV2Response get_conversation_info_v2 = 608;
  CreateConversationV2Response create_conversation_v2 = 609;
  GetConversationInfoListV2Response get_conversation_info_list_v2 = 610;
  EmptyActionResponse dissolve_conversation = 614;
  ConversationAddParticipantsResponse conversation_add_participants = 650;
  ConversationRemoveParticipantsResponse conversation_remove_participants = 651;
  ConversationSetRoleResponse conversation_set_role = 653;
  RecallMessageResponse recall_message = 702;
  ModifyMessagePropertyResponse modify_message_property = 705;
  SetConversationCoreInfoResponse set_conversation_core_info = 902;
  GetConversationSettingInfoResponse get_conversation_setting_info = 920;
  SetConversationSettingInfoResponse set_conversation_setting_info = 921;
  ConversationListResponse conversation_list = 2006;
  AckConversationApplyResponse ack_conversation_apply = 2025;
  GetConversationAuditListResponse get_conversation_audit_list = 2027;
  GetFriendReceiveApplyListResponse get_friend_receive_apply_list = 2048;
  EmptyActionResponse reply_friend_apply = 2049;
  GetRecentStrangerMessageRespBody get_recent_stranger_message = 12047;
  // stranger_list 实测服务端限流返回空 body，留空响应承接
  EmptyActionResponse stranger_conversation_list = 1000;
  GetReadIndexResponse get_read_index = 2000;
  GetMinIndexResponse get_min_index = 2001;
  GetUserMessageResponse get_user_message = 12048;
  // delete/leave/readIndex 服务端返回空 body，留空响应承接
  EmptyActionResponse delete_conversation = 603;
  EmptyActionResponse leave_conversation = 652;
  EmptyActionResponse get_conversation_participants_read_index = 2038;
  MgetConversationParticipantsResponse mget_conversation_participants_body = 654;
  PullMarkMessageResponse pull_mark_message_body = 2037;
  GetCmdMessageResponse get_cmd_message_body = 2040;
  GetMessageRangeResponse get_message_info_by_index_v2_range_body = 2041;
  MessageByInitResponse message_by_init = 2043;
  MessageByInitResponse thread_message_by_init = 2204;
  GetMessageByIdResponse get_message_by_id_body = 211;
  GetMessagesByIdListResponse get_messages_by_id_list_body = 212;
  GetConversationMessagesByTimeResponse get_conversation_messages_by_time_body = 310;
  MarkMessageResponse mark_message_body = 2036;
  ModifyMessageExtResponse modify_message_ext_body = 2021;
  GetCmdMessageRangeResponse get_cmd_message_range_body = 12040;
  GetSpecifiedMessageListResponse conversation_specified_message_list_body = 12050;
  ConversationListV2Response get_conversation_info_list_by_favorite_v2_body = 611;
  ConversationListV2Response get_conversation_info_list_by_top_v2_body = 612;
  EmptyActionResponse batch_mark_read_body = 613;
  BatchDeleteConversationResponse batch_delete_conversation_body = 619;
  ClearConversationMessageV2Response clear_conversation_message_v2_body = 620;
  GetConversationMemberListResponse get_conversation_member_list_body = 12060;
  BatchGetConversationMemberListResponse batch_get_conversation_member_list_body = 12061;
  GetRecentCmdConvResponse get_recent_cmd_conv = 12062;
  GetRecentStrangerConvResponse get_recent_stranger_conv = 12063;
  UpdateThreadSubscribeStatusResponse update_thread_subscribe_status = 2205;
}

message GetRecentStrangerMessageReqBody {
  int64 latest_stranger_version = 1;
  int64 earliest_stranger_version = 2;
  string source = 3;
  int32 new_user = 4;
  map<string, string> ext = 5;
  string biz_info = 6;
}

message ConversationRecentMessage {
  int64 conversation_short_id = 1;
  repeated ConversationMessage messages = 2;
  int64 version = 3;
  int64 badge_count = 4;
  string conversation_id = 5;
  repeated ConversationMessage ext_messages = 6;
  int32 conversation_type = 11;
  int64 parent_conv_short_id = 12;
  int64 root_message_id = 14;
}

message GetRecentStrangerMessageRespBody {
  int64 next_stranger_version = 1;
  repeated ConversationRecentMessage messages = 2;
  bool has_more = 3;
}

message EmptyActionResponse {}

message ModifyMessagePropertyResponse {
  int32 status = 1;
  int64 version = 2;
}

message Profile {
  string nick_name = 1;
  string protrait = 2;
  string basic_ext_info = 3;
  string detail_ext_info = 4;
  int64 uid = 5;
}

message ApplyUserInfo {
  int64 user_id = 1;
  int64 apply_time_second = 2;
  map<string, string> ext = 3;
  int32 status = 4;
  Profile profile = 5;
}

message GetFriendReceiveApplyListResponse {
  int64 next_cursor = 1;
  bool has_more = 2;
  repeated ApplyUserInfo user_list = 3;
  int64 total_count = 4;
}

message NewFriendMessageNotify {
  int32 message_type = 1;
  int64 from_id = 2;
  int64 to_id = 3;
  string content = 4;
  map<string, string> ext = 5;
}

message CreateConversationV2Response {
  int64 check_code = 2;
  ConversationV2 conversation = 3;
  string extra_info = 4;
  int32 status = 5;
}

message ConversationApplyInfo {
  int64 user_id = 1;
  int64 conv_short_id = 2;
  int32 conversation_type = 3;
  int32 apply_status = 4;
  int64 apply_id = 5;
  int64 create_time = 6;
  int64 modify_time = 7;
  int64 modify_user = 8;
  string sec_uid = 9;
  int64 invite_user_id = 10;
  string sec_invite_uid = 11;
  map<string, string> ext = 12;
  string apply_reason = 13;
}

message AckConversationApplyResponse {
  ConversationApplyInfo apply_info = 1;
  int32 status = 2;
  int64 check_code = 3;
  string check_message = 4;
}

message GetConversationAuditListResponse {
  repeated ConversationApplyInfo apply_info_list = 1;
  int64 next_cursor = 2;
  bool has_more = 3;
}

message ConversationAddParticipantsResponse {
  repeated int64 success_participants = 1;
  repeated int64 failed_participants = 2;
  int32 status = 3;
  string extra_info = 4;
  int64 check_code = 5;
  string check_message = 6;
  repeated SecUidPair sec_success_participants = 7;
  repeated SecUidPair sec_failed_participants = 8;
}

message SecUidPair {
  int64 uid = 1;
  string sec_uid = 2;
}

message ConversationParticipant {
  int64 user_id = 1;
  int64 sort_order = 2;
  int32 role = 3;
  string alias = 4;
  string sec_uid = 5;
  int32 blocked = 6;
  int64 left_block_time = 7;
  map<string, string> ext = 8;
}

message ConversationParticipantsPage {
  repeated ConversationParticipant participants = 1;
  bool has_more = 2;
  int64 cursor = 3;
}

message ConversationParticipantsListResponse {
  ConversationParticipantsPage participants_page = 1;
}

message ConversationSetRoleResponse {
  repeated int64 success_participants = 1;
  repeated int64 failed_participants = 2;
  int32 status = 3;
  string extra_info = 4;
  int64 check_code = 5;
  string check_message = 6;
}

message ConversationRemoveParticipantsResponse {
  repeated int64 failed_participants = 1;
  int32 status = 2;
  string extra_info = 3;
  int64 check_code = 4;
  string check_message = 5;
}

message SetConversationCoreInfoResponse {
  int32 status = 2;
  string extra_info = 3;
  int64 check_code = 4;
  string check_message = 5;
}

message SetConversationSettingInfoResponse {
  ConversationSettingInfo conversation_setting_info = 1;
  int32 status = 2;
  int64 check_code = 3;
  string check_message = 4;
  string extra_info = 5;
}

message GetConversationSettingInfoResponse {
  ConversationSettingInfo conversation_setting_info = 1;
  int32 status = 2;
  int64 check_code = 3;
  string check_message = 4;
  string extra_info = 5;
}

message ConversationSettingInfo {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int32 mute = 6;
  int32 stick_on_top = 7;
  int32 inbox_type = 8;
  int32 favorite = 11;
}

message ConversationListResponse {
  repeated Conversation conversations = 1;
}

message RecallMessageResponse {
  int32 status = 1;
}

message NewMessageNotify {
  reserved 1;
  string conversation_id = 2;
  int32 conversation_type = 3;
  int32 notify_type = 4;
  ConversationMessage message = 5;
}

message NewP2PMessageNotify {
  reserved 1;
  string conversation_id = 2;
  int32 conversation_type = 3;
  ConversationMessage message = 4;
}

message MarkConversationReadNotify {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 read_message_index = 3;
  int64 read_message_index_v2 = 4;
}

message ConversationInfoUpdatedNotify {
  Conversation conversation = 1;
}

message InboxResponse {
  repeated ConversationMessage messages = 1;
  repeated Conversation conversations = 2;
  int64 next_cursor = 3;
  int32 inbox_unread_count = 4;
  int32 has_more = 5;
  int32 filter_type = 6;
  int32 total_count = 7;
  int64 min_cursor = 8;
  int64 max_cursor = 9;
}

message ConversationV2 {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  string ticket = 4;
  ConversationParticipantsPage first_page_participants = 6;
  int32 participants_count = 7;
  bool is_participant = 8;
  int32 inbox_type = 9;
  int32 badge_count = 10;
  ConversationCoreInfo conversation_core_info = 50;
}

message ConversationCoreInfo {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 info_version = 4;
  string name = 5;
  string desc = 6;
  string icon = 7;
  int32 inbox_type = 8;
  string notice = 9;
  map<string, string> ext = 11;
  int64 owner = 12;
  string sec_owner = 13;
  int64 creator_uid = 17;
  int64 create_time = 18;
}

message Conversation {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  string ticket = 4;
  int32 inbox_type = 5;
  ConversationMembers members = 6;
  int64 min_index = 10;
  int64 max_index = 11;
  int64 unread_count = 15;
  ConversationLastSender last_sender = 20;
  ConversationExtInfo ext_info = 50;
  ConversationUserSetting user_setting = 51;
}

message ConversationMembers {
  repeated ConversationMember members = 1;
}

message ConversationMember {
  int64 uid = 1;
  int32 role = 3;
  string sec_uid = 5;
}

message ConversationLastSender {
  int64 sender_uid = 1;
  int32 status = 3;
  string nickname = 4;
  string sec_uid = 5;
}

message ConversationExtInfo {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_active_time = 4;
  string name = 5;
  string avatar = 7;
  int64 owner_uid = 12;
  string owner_sec_uid = 13;
  int64 create_time = 18;
}

message ConversationUserSetting {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_msg_time = 10;
}

message SendMessageResponse {
  int64 server_message_id = 1;
  string extra_info = 2;
  int32 status = 3;
  string client_message_id = 4;
  int64 check_code = 5;
  string check_message = 6;
}

message ConversationMessagesResponse {
  repeated ConversationMessage messages = 1;
  int64 next_cursor = 2;
  bool has_more = 3;
}

message ConversationMessage {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 server_message_id = 3;
  int64 index_in_conversation = 4;
  int64 conversation_short_id = 5;
  int32 message_type = 6;
  int64 sender = 7;
  string content = 8;
  map<string, string> ext = 9;
  int64 create_time = 10;
  int64 version = 11;
  int32 status = 12;
  int64 order_in_conversation = 13;
  string sec_sender = 14;
  int64 index_in_conversation_v2 = 17;
}

// cmd=1001 stranger/get_conversation_list —— 陌生人会话列表，body oneof 占 tag=1000。
// HAR 实测被网关限流（statusCode=409 空 body），schema 按请求方向还原；
// 游标/来源/场景三字段语义为推测。
message StrangerConversationListRequest {
  int64 cursor = 1;
  int32 source = 2;
  int32 scene = 3;
}

// cmd=2000 conversation/get_read_index —— 按会话批量查各成员已读游标（微秒时间戳量级）
message GetReadIndexRequest {
  int64 conversation_short_id = 1;
  int32 conversation_type = 2;
  string conversation_id = 3;
}

message ReadIndexItem {
  int64 uid = 1;
  int64 read_index = 3;
  // 附加计数（如已读消息条数），语义推测
  int64 extra = 4;
}

message GetReadIndexResponse {
  repeated ReadIndexItem read_index_list = 1;
}

// cmd=2001 conversation/get_min_index —— 按会话批量查最小同步游标（与 get_read_index 同形）
message GetMinIndexRequest {
  int64 conversation_short_id = 1;
  int32 conversation_type = 2;
  string conversation_id = 3;
}

// cmd=2038 conversation/batch_get_conversation_participants_readindex —— 批量查询所有成员已读游标
message GetConversationParticipantsReadIndexRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 get_user_read_index = 4;
}

message MinIndexItem {
  int64 uid = 1;
  int64 min_index = 3;
}

message GetMinIndexResponse {
  repeated MinIndexItem min_index_list = 1;
}

// cmd=2010 client/ack —— 客户端消息回执（type=500 到达/已读确认）。
// HAR 响应仅 envelope 成功帧，无 payload body。
message ClientAckRequest {
  int64 server_message_id = 1;
  int32 message_type = 2;
  int32 status = 3;
  // 附加消息体原样透传（native 里携带会话诊断信息，结构不固定用 bytes 承接）
  bytes extra = 4;
  int64 client_message_id = 5;
  int64 conversation_short_id = 6;
  int32 count = 7;
}

// cmd=12048 message/get_user_message —— 增量拉会话/消息，同时下发 cmd 链路版本游标
message GetUserMessageRequest {
  int64 version = 1;
  int64 cmd_index = 2;
  int64 stranger_version = 3;
  int64 read_version = 4;
  string source = 5;
  int64 consult_version = 6;
  int64 notify_version = 17;
  int64 thread_version = 19;
  int64 thread_read_version = 20;
  bool need_recent_conv_read_info = 21;
  int64 cmd_message_chain_v2_index = 22;
}

message GetRecentMsgVersionRange {
  int64 left_side = 1;
  int64 right_side = 2;
}

message GetRecentMessageRespBody {
  int64 next_conversation_version = 1;
  repeated ConversationRecentMessage messages = 2;
  bool has_more = 3;
  GetRecentMsgVersionRange range = 4;
}

message GetCmdMessageChainV2RespBody {
  repeated ConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_cmd_message_chain_v2_index = 3;
}

message GetUserMessageResponse {
  GetRecentMessageRespBody messages = 1;
  GetCmdMessageResponse cmd_messages = 2;
  bool has_stranger_message = 3;
  GetCmdMessageChainV2RespBody cmd_message_chain_v2 = 19;
  int64 max_cmd_message_conv_version = 20;
}

// cmd=654 conversation/batch_get_member_list —— 按 uid 精确取成员，不必拉全量
message MgetConversationParticipantsRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  repeated int64 participants = 4;
}

message MgetConversationParticipantsResponse {
  repeated ConversationParticipant participants = 1;
}

// cmd=2037 message/pull_mark —— 按标记位增量拉消息
message PullMarkMessageRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 cursor = 4;
  int64 limit = 5;
  bool asc = 6;
  int32 action_type = 7;
  int64 tag = 8;
  bool clear_unread_count = 9;
}

// 服务端字段顺序按参考 proto；消息体复用 ConversationMessage，隐藏字段解码时忽略
message PullMarkMessageResponse {
  repeated ConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_cursor = 3;
}

// cmd=2040 conversation/get_recent_cmd_conv —— 拉取最近的控制类消息
message GetCmdMessageRequest {
  int64 cmd_index = 1;
  string source = 2;
  int32 new_user = 3;
}

message GetCmdMessageResponse {
  repeated ConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_cmd_index = 3;
  int64 next_user_message_cursor = 4;
  int64 readconv_version = 5;
}

// cmd=2041 message/get_message_by_index_v2_range —— 按会话内 v2 索引区间取消息
message GetMessageRangeRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 min_index_in_conversation_v2 = 4;
  int64 max_index_in_conversation_v2 = 5;
  int32 direction = 6;
}

message MessageInfo {
  int32 status = 1;
  ConversationMessage body = 2;
}

message GetMessageRangeResponse {
  repeated MessageInfo infos = 1;
  int64 next_index_in_conversation_v2 = 2;
  bool has_more = 3;
}

// cmd=2043 message/get_message_by_init —— 冷启动拉首屏消息
message MessageByInitRequest {
  int64 version = 1;
  int32 page = 2;
}

// 包装层只保留会话标识，其余字段解码时忽略
message InitConversation {
  string conversation_id = 1;
  int32 conversation_type = 2;
}

message InitConversationMessage {
  InitConversation conversations = 1;
  repeated ConversationMessage messages = 2;
  InitThreadBubble thread_bubble_message = 3;
}

// 盖楼消息：消息体与普通消息同形，只多一个方向
message InitThreadBubble {
  repeated ConversationMessage bubble_messages = 3;
  int32 message_direction = 4;
}

message MessageByInitResponse {
  repeated InitConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_init_version = 3;
  int64 version = 4;
  int64 user_cursor = 5;
  int64 cmd_index = 6;
  int64 readconv_version = 7;
  int64 cmd_message_chain_v2_index = 8;
  int64 cmd_message_conv_version = 9;
}

// cmd=2204 message/get_thread_message_by_init —— 盖楼消息冷启动
message ThreadMessageByInitRequest {
  int64 thread_version = 1;
  int32 thread_limit = 2;
  int32 msg_limit = 3;
}

// cmd=211 message/get_message_by_server_id —— 按服务端消息 id 取单条
message GetMessageByIdRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 server_message_id = 4;
  bool only_status = 5;
}

message GetMessageByIdResponse {
  MessageInfo msg_info = 1;
}

// cmd=212 message/get_messages_by_server_id_list —— 批量取消息
message GetMessagesByIdListRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  repeated int64 server_message_id_list = 4;
}

message GetMessagesByIdListResponse {
  repeated MessageInfo msg_info_list = 1;
}

// cmd=310 message/get_from_conversation_by_time —— 按时间正序翻页
message GetConversationMessagesByTimeRequest {
  int64 conv_short_id = 1;
  int64 earliest_timestamp = 2;
  int64 cursor = 3;
  int64 limit = 4;
}

message GetConversationMessagesByTimeResponse {
  bool has_more = 1;
  int64 next_cursor = 2;
  repeated MessageInfo message_list = 3;
}

// cmd=2036 message/mark —— 消息标记/取消标记
message MarkMessageRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 server_message_id = 4;
  int32 do_action = 5;
  int32 action_type = 6;
  int64 sort_time = 7;
  int64 tag = 8;
}

message MarkMessageResponse {
  int64 server_message_id = 1;
  int64 check_code = 2;
  string check_message = 3;
  int32 status = 4;
}

// cmd=2021 message/modify_ext —— 修改消息扩展与内容
message ModifyMessageExtRequest {
  int64 conversation_short_id = 1;
  int64 message_id = 2;
  string ticket = 3;
  map<string, string> ext = 4;
  bool is_edited = 5;
  string content = 6;
  int32 conversation_type = 7;
  int32 message_type = 8;
  string conversation_id = 9;
}

message ModifyMessageExtResponse {
  map<string, string> ext = 1;
  int64 version = 2;
}

// cmd=12040 message/get_cmd_message_range —— 控制类消息区间
message GetCmdMessageRangeRequest {
  int64 cmd_index_v2 = 1;
  int64 size = 2;
  int32 direction = 3;
  int64 cmd_message_chain_v2_index = 4;
}

message GetCmdMessageRangeResponse {
  int64 cmd_index_v2 = 1;
  int64 size = 2;
  int32 direction = 3;
  repeated ConversationMessage messages = 4;
  int64 next_cmd_index_v2 = 5;
  int64 cmd_message_chain_v2_index = 6;
  int64 next_cmd_message_chain_v2_index = 7;
}

// cmd=12050 conversation/specified_message_list —— 指定类型消息列表
message GetSpecifiedMessageListRequest {
  int32 message_list_type = 1;
  int64 conversation_short_id = 2;
  int64 offset = 3;
  int64 count = 4;
}

message GetSpecifiedMessageListResponse {
  repeated ConversationMessage message_list = 1;
  int64 next_offset = 2;
  bool has_more = 3;
}

// cmd=611/612 conversation/get_by_favorite|get_by_top —— 收藏/置顶会话
message GetConversationInfoListByFavoriteRequest {
  int64 cursor = 1;
  int64 limit = 2;
}

message GetConversationInfoListByTopRequest {
  int64 cursor = 1;
  int64 limit = 2;
  int32 conversation_type = 3;
}

message ConversationListV2Response {
  repeated ConversationV2 conversation_info_list = 1;
  bool has_more = 2;
  int64 next_cursor = 3;
}

// cmd=613 conversation/batch_mark_read —— 批量已读
message BatchMarkConversationReadRequest {
  repeated MarkConversationReadRequest mark_read_requests = 1;
}

// cmd=619 conversation/batch_delete —— 批量删除会话
message BatchDeleteConversationRequest {
  repeated DeleteConversationRequest mark_delete_requests = 1;
}

message BatchDeleteConversationResponse {
  repeated int64 failed_conversation_short_ids = 1;
}

// cmd=620 conversation/clear_message —— 清空会话消息
message ClearConversationMessageRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_message_index = 4;
  int64 last_message_index_v2 = 5;
  int64 last_msg_badge_count = 6;
  int64 last_message_time = 8;
  int64 total_thread_important_badge_count = 9;
}

message ClearConversationMessageV2Response {
  bool show_empty_conv = 1;
}

// cmd=12060/12061 conversation/get_member_list|batch_get_member_list —— 成员列表
message GetConversationMemberListRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int32 sync_scene = 4;
  int64 local_member_version = 5;
  int64 cursor = 6;
  int64 limit = 7;
}

message ConversationMemberList {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 member_version = 4;
  int64 participants_count = 5;
  ConversationParticipantsPage full_participants_page = 6;
  int64 check_code = 100;
  string check_msg = 101;
}

message GetConversationMemberListResponse {
  ConversationMemberList member_list = 1;
}

message BatchGetConversationMemberListRequest {
  repeated GetConversationMemberListRequest batch_member_list = 1;
}

message BatchGetConversationMemberListResponse {
  repeated ConversationMemberList batch_member_list = 1;
}

// cmd=12062 conversation/get_recent_cmd_conv —— 最近控制类消息会话
message GetRecentCmdConvRequest {
  int64 cmd_message_conv_version = 1;
  bool reverse = 2;
  string source = 3;
}

message GetRecentCmdConvResponse {
  repeated ConversationV2 conversation_info = 1;
  bool has_more = 2;
  int64 next_cmd_message_conv_version = 3;
}

// cmd=12063 conversation/get_recent_stranger_conv —— 最近陌生人会话
message GetRecentStrangerConvRequest {
  int64 max_version = 1;
  int64 min_version = 2;
  bool reverse = 3;
  string source = 4;
}

message GetRecentStrangerConvResponse {
  repeated ConversationV2 conversation_info = 1;
  bool has_more = 2;
  int64 next_version = 3;
}

// cmd=2205 conversation/update_thread_subscribe_status —— 盖楼订阅状态
message UpdateThreadSubscribeStatusRequest {
  string thread_id = 1;
  int64 thread_short_id = 2;
  int32 status = 3;
}

message UpdateThreadSubscribeStatusResponse {
  int32 status = 1;
}
`

let root: protobuf.Root | undefined

/** 解析内联 proto（keepCase=false，与参考项目 protobuf.load 行为一致），进程内缓存 */
export function loadRoot (): protobuf.Root {
  root ??= protobuf.parse(IM_PROTO_SOURCE, { keepCase: false }).root
  return root
}
