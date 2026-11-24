/** App 域（Android 40.5.0 协议）公共类型 */
import type { Log } from '../types.js'

/** 设备画像：不含身份标识，身份统一放 Ids */
export interface Dev {
  aid: number
  appName: string
  packageName: string
  versionCode: number
  versionName: string
  manifestVersionCode: number
  updateVersionCode: number
  devicePlatform: string
  os: string
  osApi: number
  osVersion: string
  /** 系统 build 号：UA 与注册体的 release_build 必须一致，否则画像是两个系统 */
  build: string
  /** rom_version：注册体与 ticket-guard 的 display-os-version 同源 */
  romVersion: string
  resolution: string
  dpi: number
  deviceType: string
  deviceBrand: string
  cpuSupport64: string
  hostAbi: string
  channel: string
  ac: string
  mccMnc: string
  ssmix: string
  appTheme: string
}

/** 设备标识：device_register 产出，调用方持久化后回传给 device()/login() */
export interface Ids {
  device_id: string
  iid: string
  cdid: string
  clientudid: string
  openudid: string
  klink_egdi: string
  device_token: string
  req_id: string
  oaid: string
  first_install: number
  new_user?: number
  device_id_str?: string
  install_id_str?: string
  dtrait_pk1?: string
  dtrait_pk2?: string
  dtrait_pk1_version?: string
  dtrait_pk2_version?: string
  dtrait_token?: string
  dtrait_version?: number
  bind_dtrait?: boolean
  device_dtrait?: string
  device_dtrait_token?: string
  client_key?: string
  source?: string
  /** 注册时服务端下发的设备级 cookie（odin_tt 等），passport 会话缺它会被判 7 */
  cookie?: string
}

/** 服务端二次验证方式（assist_ 前缀 = 安全手机） */
export interface VerifyWay {
  verify_way?: string
  /** 发起验证时必须回带的动作类型；缺失的方式无法自动完成 */
  act_type?: string | number
  mobile?: string
  sms_content?: string
  channel_mobile?: string
  description?: string
  [key: string]: unknown
}

export interface MfaCtx {
  encrypt_uid?: string
  not_login_ticket?: string
  verify_ticket?: string
  biz_params?: Record<string, unknown> | string
  common_params?: Record<string, unknown> | string
  event_params?: Record<string, unknown> | string
  verify_ways?: VerifyWay[]
}

/** login/check_qrconnect 的 envelope */
export interface Envelope<T> {
  message: string
  data: T
}

/** 登录成功 data 的常用字段 */
export interface LoginData {
  user_id?: string
  user_id_str?: string
  uid?: string
  sec_user_id?: string
  session_key?: string
  sessionid?: string
  screen_name?: string
  name?: string
  avatar_url?: string
  mobile?: string
  has_password?: number
  error_code?: number
  description?: string
  [key: string]: unknown
}

export interface QrUser {
  user_id?: number
  user_id_str?: string
  sec_user_id?: string
  screen_name?: string
  name?: string
  avatar_url?: string
  mobile?: string
  [key: string]: unknown
}

/** 扫码轮询 data */
export interface Check {
  status?: 'new' | 'scanned' | 'confirmed' | 'expired' | 'canceled' | (string & {})
  error_code?: number
  account_flow?: string
  encrypt_uid?: string
  biz_params?: Record<string, unknown>
  common_params?: Record<string, unknown>
  verify_ways?: VerifyWay[]
  verify_center_decision_conf?: string | Record<string, unknown>
  verify_center_secondary_decision_conf?: string | Record<string, unknown>
  verify_ticket?: string
  captcha?: string
  description?: string
  desc_url?: string
  redirect_url?: string
  user_data?: QrUser
  [key: string]: unknown
}

export interface CaptchaCredential {
  captcha?: string
  verifyTicket?: string
  sharkTicket?: string
  mobileTicket?: string
}

/** 设备注册/登录/IM 共用入参 */
export interface AppOpts {
  /** 已有登录 Cookie（sessionid=...）；注入后 token()/info() 直接可用 */
  cookie?: string
  /** 已持久化的设备标识；省略时 device() 自动注册 */
  ids?: Partial<Ids>
  /** 覆盖设备画像字段 */
  dev?: Partial<Dev>
  log?: Log
}
