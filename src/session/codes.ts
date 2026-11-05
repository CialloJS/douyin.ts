/** IM 域常量：站点、接口路径、缓存与协议固定值集中一处，避免魔法值散落 */
export const site = {
  im: 'https://imdesktop.douyin.com',
  web: 'https://www.douyin.com',
  edge: 'https://www-hj.douyin.com',
  api: 'https://imapi.douyin.com',
  apiAlt: 'https://imapi3-normal.zijieapi.com',
  vod: 'https://vod.bytedanceapi.com/',
  cdn: 'https://p3-sign.douyinpic.com/obj/im-resource/',
  referer: 'https://www.douyin.com/',
  peer: 'https://vc-gate-edge.ndcpp.com/sdk/get_peer',
} as const

export const api = {
  activeUpdate: '/aweme/v1/web/im/user/active/update/?action=heartbeat&new_user_login=0',
  activeStatus: '/aweme/v1/web/im/user/active/status/',
  activeConfig: '/aweme/v1/web/im/user/active/config/get',
  readSwitch: '/aweme/v1/web/im_communication/msg_read_switch/',
  noticeCount: '/aweme/v1/web/notice/count/',
  notice: '/aweme/v1/web/notice/',
  desktopSetting: '/aweme/v1/im/desktop/setting/get',
  userSettings: '/aweme/v1/web/user/settings/',
  compliance: '/aweme/v1/web/compliance/settings/',
  familiar: '/aweme/v1/web/familiar/list/',
  bubble: '/aweme/v1/web/im/bubble/detail_list/',
  spotlight: '/aweme/v1/web/im/spotlight/relation',
  follow: '/aweme/v1/web/commit/follow/user/',
  shareVerify: '/aweme/v1/web/im_group_api/share/verification/',
  userInfo: '/aweme/v1/web/im/user/info/',
  profileScene: '/aweme/v1/web/user/profile/scene/',
  profileOther: '/aweme/v1/web/user/profile/other/',
  profileSelf: '/aweme/v1/web/user/profile/self/',
  playInfo: '/maya/story/batch_play_info/v1/',
  awemeDetail: '/aweme/v1/web/multi/aweme/detail/',
  emojiList: '/aweme/v1/web/emoji/list/',
  resourceList: '/aweme/v1/web/im/resource/list/aggregation/',
  stickerCollect: '/aweme/v1/web/im/resource/sticker/collect/',
  trending: '/aweme/v1/web/im/resources/emoticon/trending',
  strategy: '/aweme/v1/web/im/strategy/config',
  privacy: '/aweme/v1/web/privacy/batch_build_image/',
  uploadConfig: '/aweme/v1/web/im/upload/config/v2',
  danmaku: '/aweme/v1/web/danmaku/get_v2/',
  playProgress: '/aweme/v1/web/play/progress/',
  seriesRecord: '/aweme/v1/web/series/watch/record/',
  mixRecord: '/aweme/v1/web/mix/watch/record/',
  history: '/aweme/v1/web/history/write/',
  safety: '/aweme/v2/video/safety/check/',
  upload: '/upload/v1/',
  accountInfo: '/passport/account/info/v2/',
  tokenBeat: '/passport/token/beat/web/',
} as const

export const time = {
  emoji: 300_000,
  trending: 300_000,
} as const

export const vod = {
  region: 'cn-north-1',
  service: 'vod',
  part: 5 * 1024 * 1024,
} as const

/** 接口携带的固定版本号与 aid */
export const ver = {
  beat: '1.2.13',
  webAid: 6383,
} as const

/** 验证 / WS 请求头复用值 */
export const ws = {
  sdk: '2',
  passport: '601504',
  dp: '1128',
  region: 'cn',
  regionSrc: 'uid',
  kmsv: '1',
  qos: '1',
  ack: '1',
} as const

const frontierHost = 'wss://frontier-aweme-lf-ipainner.amemv.com'

/** 协议固定值：SDK 身份、Frontier 地址、体量限制 */
export const cmd = {
  bodyless: [50005] as number[],
  host: frontierHost,
  frontier: `${frontierHost}/ws/v2`,
  appKey: 'e1bd35ec9db7b8d846de66ed140b1ad9',
  salt: 'f8a69f1719916z',
  ua: 'okhttp/3.12.1 com.ss.android.ugc.aweme/280400',
  sdk: '5.0.3.0-rc.11-SNAPSHOT',
  version: '0.7.2-fix.1',
  build: '2f4951d:fix/douyin-creator-fix',
  depth: 8,
} as const
