/** 二维码取码与 check_qrconnect 轮询主循环 */
import { err, isErr } from '../../error.js'
import { encodeForm, passportBaseQuery, signQuery } from '../sign/qs.js'
import { passport } from '../sign/const.js'
import { verifyDecision } from '../res.js'
import { createLog } from '../log.js'
import type { Http } from '../http.js'
import { ec, fld, msg, path, qr, st, tag, time } from './codes.js'
import { qrBody, sdkSourceInfo, signExtras } from './body.js'
import { verifyCenter } from './verify.js'
import { mfa, sleep } from './mfa.js'
import { sessionOf } from './session.js'
import type {
  CheckData,
  CheckResult,
  Envelope,
  GetQrData,
  LoginOpts,
  QrResult,
  Session,
} from './types.js'

/** 默认 SDK 内部日志:登录链路失败原因需可见,静默轮询会让卡点无从定位 */
const log = createLog({ tag })

/** message 恒为 sdk,日志必须补 data 才能定位 */
const why = (error: unknown): string =>
  isErr(error)
    ? JSON.stringify(error.data)
    : error instanceof Error ? error.message : String(error)

/** 频控等不可重试错误:带 fatal 标记,穿透轮询 catch 直接终止 */
const fatal = (error: unknown): boolean =>
  isErr(error) && (error.data as { fatal?: boolean } | undefined)?.fatal === true

/** GET /passport/web/get_qrcode/,返回二维码 token 与 base64 图片 */
export async function getQr (http: Http): Promise<QrResult> {
  const query = passportBaseQuery({
    deviceId: http.deviceId,
    installId: http.installId,
    accountSdkSourceInfo: sdkSourceInfo(http),
    bizTraceId: http.bizTraceId,
    next: qr.next,
    extra: { need_logo: qr.needLogo, need_short_url: qr.needShort },
  })
  const { search } = signQuery(query, {}, signExtras(http))
  const url = `${passport.origin}${path.qrcode}?${search}`
  const res = await http.json<Envelope<GetQrData>>(url, {
    headers: http.passportHeaders(url),
  })
  const d = res.data.data
  if (d.error_code !== 0) err(res.data)
  return { token: d.token, base64: d.qrcode, indexUrl: d.qrcode_index_url }
}

/**
 * POST /passport/web/check_qrconnect/;postSign 为 MFA biz 参数,在签名之后追加进 body
 * (HAR 实证:确认轮 sign 只覆盖基础 body,std_verify_* 不参与签名)
 */
export async function checkQr (
  http: Http,
  token: string,
  postSign?: Record<string, string>,
  fp?: string,
): Promise<CheckResult> {
  const body = qrBody(token)
  const query = passportBaseQuery({
    deviceId: http.deviceId,
    installId: http.installId,
    accountSdkSourceInfo: sdkSourceInfo(http),
    bizTraceId: http.bizTraceId,
    // 验证中心回填的 fp 追加进 query(HAR 实证:未验证时确认轮不带 fp)
    ...(fp ? { extra: { fp } } : {}),
  })
  const bodyWire = encodeForm(body)
  const { search } = signQuery(query, body, signExtras(http, bodyWire))
  const url = `${passport.origin}${path.check}?${search}`
  const res = await http.json<Envelope<CheckData>>(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...http.passportHeaders(url),
    },
    body: postSign ? encodeForm({ ...body, ...postSign }) : bodyWire,
  })
  return { data: res.data.data, decision: verifyDecision(res.headers) }
}

/** 轮询直至 confirmed / expired / 超时 */
export async function poll (http: Http, token: string, opts: LoginOpts): Promise<Session> {
  let deadline = Date.now() + time.timeout
  let last: CheckData | undefined
  let mfaDone = false
  let notified: string | undefined
  let extra: Record<string, string> = {}
  let fp: string | undefined
  let verifyCount = 0

  while (Date.now() < deadline) {
    let decision: string | undefined
    try {
      const res = await checkQr(http, token, extra, fp)
      last = res.data
      decision = res.decision
      const code = Number(last.error_code ?? 0)
      if (code !== 0) log.warn(`check_qrconnect error_code=${code} ${String(last.description ?? '')}`)

      // 验证中心决策:风控/滑块等非 0 error_code(1105/2046/2156)同样可能下发验证决策,
      // 必须在频控退避之前解析,否则本地验证页永远不会被拉起
      if (verifyCount < ec.verifyLimit) {
        const center = await verifyCenter(http, last, decision, opts)
        if (center) {
          verifyCount += 1
          await opts.onStatus?.(st.verifying)
          extra = { ...extra, ...center.fields }
          fp = center.fp ?? fp
          await opts.onStatus?.(st.verified)
          deadline = Date.now() + time.timeout
          // 验证完成后按轮询间隔再查,避免验证请求与紧接的 poll 挤进同一频控窗口
          await sleep(time.poll)
          continue
        }
      }

      // 短信/密码二次验证:account_flow=verify 或带 biz_params 即为服务端下发的 MFA 挑战
      // (2046 响应的 biz_params 含 std_verify_flow_id/token,每轮刷新),优先走内置流程;
      // 无可用验证方式时回退 App 侧验证提示,等待服务端放行
      if (!mfaDone && (last.account_flow === fld.accountFlow || last.biz_params != null)) {
        await opts.onStatus?.(st.verifying)
        try {
          extra = { ...extra, ...await mfa(http, last, opts) }
          mfaDone = true
          // 验证通过后按轮询间隔再查,避免验证请求与紧接的 poll 挤进同一频控窗口
          await sleep(time.poll)
        } catch (e) {
          log.warn(`二次验证不可自动完成: ${why(e)}`)
          await opts.onStatus?.(msg.appVerify)
          await sleep(time.appVerifyWait)
          continue
        }
        continue
      }

      // 访问太频繁不可重试,与官方一致直接终止,不带着频控继续轮询
      if (code === ec.tooFrequent) {
        err({ fatal: true })
      }
      // 2046 为 App 侧安全验证:提示后退避等待服务端放行
      if (code === ec.appVerify) {
        if (notified !== 'app_verify') {
          notified = 'app_verify'
          await opts.onStatus?.(msg.appVerify)
        }
        await sleep(time.appVerifyWait)
        continue
      }
    } catch (e) {
      if (fatal(e)) throw e
      log.warn(`check_qrconnect 异常: ${why(e)}`)
      await sleep(time.poll)
      continue
    }

    // 同一状态只回调一次(轮询期间 scanned 会重复出现)
    if (last.status && last.status !== notified) {
      notified = last.status
      await opts.onStatus?.(last.status)
    }
    if (last.status === st.confirmed) return sessionOf(http, last.user_data)
    if (last.status === st.expired) err(last)
    await sleep(time.poll)
  }

  err({ timeout: time.timeout, status: last?.status })
}
