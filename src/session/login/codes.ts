/** 登录链路与验证中心的常量、魔法值:协议路径、错误码、状态、验证方式、表单值与验证中心参数统一集中 */
export const tag = 'login'

/** 轮询节奏与请求超时(协议节奏,勿随意改) */
export const time = {
  poll: 1100,
  timeout: 120_000,
  upPoll: 3000,
  upTimeout: 180_000,
  appVerifyWait: 5000,
  /** 本地验证页等待上限 */
  verify: 300_000,
  /** 验证组件请求超时 */
  fetch: 30_000,
} as const

/** 扫码请求公共参数 */
export const qr = {
  needLogo: 'false',
  needShort: 'false',
  frontier: 'true',
  newLogin: '1',
  next: 'https://www.douyin.com',
} as const

export const path = {
  qrcode: '/passport/web/get_qrcode/',
  check: '/passport/web/check_qrconnect/',
  send: '/passport/web/send_code/',
  validate: '/passport/web/validate_code/',
  password: '/passport/web/account/verify/',
  pack: '/passport/safe/pack_verify_ways_data/',
  ttwid: '/ttwid/check/',
} as const

/** 登录链路里需要判断的错误码(与 SDK 的 err 抛错函数区分命名) */
export const ec = {
  tooFrequent: 7,
  appVerify: 2046,
  /** 验证中心风控/滑块兜底码 */
  risk: 1105,
  verifyLimit: 3,
} as const

export const st = {
  new: 'new',
  scanned: 'scanned',
  confirmed: 'confirmed',
  expired: 'expired',
  verifying: 'verifying',
  verified: 'verified',
} as const

export const way = {
  assistSms: 'assist_mobile_sms_verify',
  sms: 'mobile_sms_verify',
  upSms: 'assist_mobile_up_sms_verify',
  password: 'pwd_verify',
  /** 内置优先级:安全手机短信 > 绑定手机短信 > 上行短信 > 登录密码 */
  order: ['assist_mobile_sms_verify', 'mobile_sms_verify', 'assist_mobile_up_sms_verify', 'pwd_verify'] as const,
} as const

/** Passport 表单固定值 */
export const fld = {
  iid: '0',
  mixMode: '1',
  sdk: '1.0.0.428-web',
  copywriting: 'qr_connect',
  diversion: 'mfa',
  scene: 'account_login',
  template: 'ato',
  type: 'MFA',
  desktopType: '3737',
  webType: '363c',
  smsOk: 'success',
  sixDigits: '1',
  defaultSms: 'YZ',
  accountFlow: 'verify',
  service: '',
  bizKeys: [
    'passport_mfa_retry_tag',
    'std_verify_flow_id',
    'std_verify_scene',
    'std_verify_template',
    'std_verify_token',
    'std_verify_type',
    'std_verify_way',
  ] as const,
} as const

export const ck = {
  source: 'sdk_source_info',
  msToken: 'msToken',
  uid: 'uid_tt',
} as const

export const bogus = 'jumpbyte-desktop'

/** 重复的用户提示,避免多处硬编码 */
export const msg = {
  appVerify: '请前往抖音 App 完成安全验证后继续登录',
  assistSwitch: '已改用辅助手机接收验证码',
  smsOk: '短信验证通过',
  pwdOk: '密码验证通过',
} as const

/** 验证中心(风控/滑块)协议常量 */
export const vc = {
  /** 网页登录场景 aid;桌面 IM 用 im 域 aid */
  webAid: 6383,
  /** VerifyCenter 按这些 code 分发,而非嵌套 MFA 决策里的描述串 */
  codes: [10000, 20000, 30000, 40000] as number[],
  /** 决策默认场景层级(官方 iframe 由业务初始化传入) */
  scene: 'p0',
  /** 官方成功链路 captcha/get 必填业务参数(缺失即 501) */
  repo: '579047',
  h5: '4.0.26',
  extra: { scene: 'normal' },
  /** 服务端 fp 只接受 verify_* 字符串 */
  fpPrefix: 'verify_',
  /** fp 页面存储键与 Cookie 名 */
  webId: 's_v_web_id',
  /** 决策 verify_from 取值 */
  from: 'verify_center',
  captcha: 'captcha',
  /** 二次决策标记 */
  level: 'secondary',
  /** SecondVerify SDK 版本 */
  sdk: '1.0.29',
  /** vcs 配置接口与请求头标记 */
  setting: 'https://vcs.zijieapi.com/vc/setting',
  flag: '1',
  /** 官方验证码组件地址及备用地址 */
  center: 'https://lf-rc1.yhgfb-cn-static.com/obj/rc-verifycenter/verifycenter/@latest/index.js',
  centerBackups: [
    'https://lf-rc2.yhgfb-cn-static.com/obj/rc-verifycenter/verifycenter/@latest/index.js',
    'https://lf-cdn-tos.bytescm.com/obj/rc-verifycenter/verifycenter/@latest/index.js',
  ] as const,
} as const

/** 验证页代理允许访问的主机(不含协议) */
export const host = {
  im: 'imdesktop.douyin.com',
  login: 'login.douyin.com',
  web: 'www.douyin.com',
  verify: 'verify.zijieapi.com',
  vcs: 'vcs.zijieapi.com',
} as const
