/** Passport 域常量：passport = 登录链路（imdesktop 桌面端内嵌登录页），im = 桌面 IM 链路（imdesktop），web = 创作者网页链路（creator.douyin.com） */

/**
 * 桌面客户端统一按 macOS 口径伪装（对齐 douyin-im darwin 分支）：
 * 硬件注册、登录页 UA、IM query、风控参数共用同一套值，避免平台/版本互相矛盾触发更严的风控
 */
export const mac = {
  release: '24.6.0',
  model: 'Mac14,6',
  platform: 'darwin',
  channel: '20002',
  /** 内嵌登录页 UA（douyin-im DESKTOP_LOGIN_USER_AGENT） */
  loginUa: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) douyinim/1.2.1 Chrome/130.0.6723.58 Electron/33.2.0-rs.21.release.main.1 Safari/537.36',
  /** IM 数据域/媒体上传 UA（douyin-im services/im/desktop.ts） */
  ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) douyinim/1.2.1 Chrome/130.0.6723.58 Electron/33.2.0 Safari/537.36',
  /** 硬件画像与请求指纹共用同一分辨率/浏览器口径 */
  screen: '1707x1067',
  width: '1707',
  height: '1067',
  browserPlatform: 'MacIntel',
  browserName: 'Mozilla',
} as const

/**
 * 桌面客户端内嵌登录页链路（imdesktop.douyin.com 实证）：
 * 登录与 IM 同域同 aid，扫码产出 aid=339757 会话，直接用于 IM 数据域
 */
export const passport = {
  origin: 'https://imdesktop.douyin.com',
  aid: '339757',
  appKey: '3c452fb664e3de0e936108429a0bc697',
  // 桌面客户端 macOS 内嵌登录页 UA；确认轮风控评估 UA 与环境一致性，通用浏览器 UA 会触发 2156
  ua: mac.loginUa,
} as const

export const im = {
  origin: 'https://imdesktop.douyin.com',
  aid: '339757',
  version: '1.2.1',
  appKey: '3c452fb664e3de0e936108429a0bc697',
} as const

export const web = {
  origin: 'https://creator.douyin.com',
  aid: '2906',
  appKey: '6ddd3ec693f3a124adb29b91b244ece5',
} as const

/** 桌面设备注册与上报路径 */
export const reg = {
  channel: 'local_test',
  path: '/service/2/desktop/device_register/',
  alert: '/service/2/app_alert/',
} as const

/** desktop lite Passport 公共 query 固定值 */
export const lite = {
  jssdk: '5.1.2',
  type: 'lite',
  authn: '1.0.0.428-web',
  lang: 'zh',
  appLang: 'zh-CN',
  fromSdk: '1',
  fromSaas: '1',
  newLogin: '1',
  platform: 'PC',
  iid: '0',
} as const

/** 复用的响应头名 */
export const hdr = {
  verify: 'x-tt-verify-passport-decision',
  log: 'x-tt-logid',
  captcha: 'x-vc-bdturing-parameters',
} as const

export const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36'
