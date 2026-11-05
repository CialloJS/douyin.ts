/** 扫码登录的对外类型与内部 envelope/challenge 定义 */
import type { Device, Log } from '../../types.js'

export type QrStatus = 'new' | 'scanned' | 'confirmed' | 'expired' | (string & {})

export interface QrUserData {
  app_id?: number
  user_id?: number
  user_id_str?: string
  sec_user_id?: string
  screen_name?: string
  name?: string
  avatar_url?: string
  mobile?: string
  has_password?: number
  country_code?: number
  [key: string]: unknown
}

/** 服务端可选的二次验证方式(assist_ 前缀 = 安全手机) */
export interface VerifyWay {
  verify_way?: string
  mobile?: string
  sms_content?: string
  channel_mobile?: string
  [key: string]: unknown
}

export interface CheckData {
  status?: QrStatus
  error_code: number
  account_flow?: string
  encrypt_uid?: string
  biz_params?: Record<string, unknown>
  common_params?: Record<string, unknown>
  verify_ways?: VerifyWay[]
  /** 验证中心决策 conf(JSON 串或对象):需在本地验证页完成官方安全验证后重试 */
  verify_center_decision_conf?: string | Record<string, unknown>
  /** 验证中心二次决策 conf:一次验证通过后服务端可能再次下发 */
  verify_center_secondary_decision_conf?: string | Record<string, unknown>
  verify_ticket?: string
  captcha?: string
  description?: string
  desc_url?: string
  extra?: string
  redirect_url?: string
  scan_app_id?: number
  user_data?: QrUserData
  scan_user_info?: Record<string, unknown>
  scan_device_info?: Record<string, unknown>
}

/** 二次验证输入描述:kind=sms 附 maskedMobile,kind=password 需返回账号密码 */
export interface MfaInfo {
  kind?: 'sms' | 'password'
  maskedMobile?: string
}

export interface LoginOpts {
  /** 取码后回调:QR 串(扫码页 URL,兜底 token)与 base64 图,渲染权交给调用方 */
  onQr?: (qr: { url: string; base64?: string }) => void | Promise<void>
  /** 扫码状态:new/scanned/verifying/confirmed…(含中文提示文案) */
  onStatus?: (s: string) => void | Promise<void>
  /** 需本地安全验证时回调:验证页地址(浏览器打开) */
  onVerifyUrl?: (url: string) => void
  /** 触发二次验证时回调:返回短信验证码或密码;未提供则登录失败 */
  onMfa?: (info: MfaInfo) => string | Promise<string>
  /**
   * 二次验证方式拉取:触发时回调服务端全部可用方式,返回要使用的 verify_way 名称;
   * 返回 undefined 走内置优先级(安全手机短信 > 绑定手机短信 > 上行短信 > 密码)
   */
  onVerifyWays?: (ways: VerifyWay[]) => string | undefined | Promise<string | undefined>
  userAgent?: string
  /**
   * 已持久化的设备身份；注入后跳过注册（沿用同一设备登录，避免每次登录触发 MFA）。
   * 省略时注册新设备并通过 `session.device` 返回。
   */
  device?: Device
  log?: Log
}

/** 登录会话:userId 为数字 uid(frontier 握手/消息过滤需要),存储由调用方自理 */
export interface Session {
  userId: string
  cookie: string
  userData?: QrUserData
  /** 本次登录使用的设备身份;落盘后可在下次 login / new Bot 注入复用 */
  device?: Device
}

/** Passport 响应 envelope */
export interface Envelope<T> {
  message: string
  data: T
}

export interface GetQrData {
  token: string
  qrcode: string
  expire_time: number
  error_code: number
  qrcode_index_url?: string
}

/** 二维码取码结果:base64 图与扫码页地址 */
export interface QrResult {
  token: string
  base64: string
  indexUrl?: string
}

/** MFA 挑战参数 */
export interface Challenge {
  encrypt_uid?: string
  biz_params?: Record<string, unknown>
  common_params?: Record<string, unknown>
}

/** check_qrconnect 轮询结果:响应体与响应头验证决策 */
export interface CheckResult {
  data: CheckData
  decision: string | undefined
}
