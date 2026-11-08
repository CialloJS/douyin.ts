/** 二维码取码与 check_qrconnect 轮询主循环 */
import { err, isErr } from '../../error.js'
import { encodeForm, passportBaseQuery, resumeQuery, signQuery } from '../sign/qs.js'
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

/**
 * 轮询间隔按已完成的外层轮数递增:官方客户端在 60/180 轮后把间隔提到 3s/5s,
 * 固定 1s 长时间轮询会让服务端把整段登录判成频繁访问(error_code=7)
 */
const pace = (count: number): number =>
  count >= 180 ? time.pollMax : count >= 60 ? time.pollMid : time.poll

/** 去掉每轮都重算的参数,留下可原样重放的签名 query */
function strip (query: Record<string, string>): Record<string, string> {
  const copy = { ...query }
  delete copy.msToken
  delete copy.a_bogus
  return copy
}

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
 * POST /passport/web/check_qrconnect/;postSign 为验证字段,在签名之后追加进 body
 * (HAR 实证:确认轮 sign 只覆盖基础 body,std_verify_* 不参与签名);
 * resume 为验证完成后的重放签名,官方只补 fp 与验证字段而不重算 sign/qs
 */
export async function checkQr (
  http: Http,
  token: string,
  postSign?: Record<string, string>,
  fp?: string,
  resume?: Record<string, string>,
): Promise<CheckResult> {
  const body = qrBody(token)
  const bodyWire = postSign ? encodeForm({ ...body, ...postSign }) : encodeForm(body)
  const extras = signExtras(http, bodyWire)
  const signed = resume
    ? resumeQuery(fp ? { ...resume, fp } : resume, extras)
    : signQuery(passportBaseQuery({
      deviceId: http.deviceId,
      installId: http.installId,
      accountSdkSourceInfo: sdkSourceInfo(http),
      bizTraceId: http.bizTraceId,
      // 验证中心回填的 fp 追加进 query(HAR 实证:未验证时确认轮不带 fp)
      ...(fp ? { extra: { fp } } : {}),
    }), body, extras)
  const url = `${passport.origin}${path.check}?${signed.search}`
  const res = await http.json<Envelope<CheckData>>(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...http.passportHeaders(url),
    },
    body: bodyWire,
  })
  return {
    data: res.data.data,
    message: res.data.message,
    decision: verifyDecision(res.headers),
    signed: strip(signed.query),
  }
}

/** 轮询直至 confirmed / expired / 超时 */
export async function poll (http: Http, token: string, opts: LoginOpts): Promise<Session> {
  let deadline = Date.now() + time.timeout
  let last: CheckData | undefined
  let notified: string | undefined
  let extra: Record<string, string> = {}
  let fp: string | undefined
  let signed: Record<string, string> | undefined
  // 验证完成后是同一轮外层轮询的重放:不计数、不等待、沿用失败那一轮的签名
  let replay = false
  let count = 0
  let verifyCount = 0
  let mfaDone = false
  let frequent = 0
  // 暂时性失败预算(错误码 6/超时)与响应异常预算(无错误码),与官方一致各 3 次
  let transient = 0
  let missing = 0

  const retry = (code: unknown): boolean => {
    if ((code === 6 || code === 'ECONNABORTED') && transient < 3) {
      transient += 1
      return true
    }
    if (!code && missing < 3) {
      missing += 1
      return true
    }
    return false
  }

  while (Date.now() < deadline) {
    if (!replay) count += 1
    let res: CheckResult
    try {
      res = await checkQr(http, token, extra, fp, replay ? signed : undefined)
    } catch (e) {
      const code = isErr(e)
        ? (e.data as { error_code?: unknown } | undefined)?.error_code
        : undefined
      if (!retry(code)) throw e
      log.warn(`check_qrconnect 异常: ${why(e)}`)
      await sleep(pace(count))
      replay = false
      continue
    }
    last = res.data
    signed = res.signed
    const code = Number(last.error_code ?? 0)
    // 成功只看 envelope 的 message:频控等异常也可能带 error_code=0 的 data
    const ok = res.message === 'success'
    if (!ok) log.warn(`check_qrconnect error_code=${code} ${String(last.description ?? '')}`)

    // 验证中心只按服务端显式下发的决策拉起:错误码本身不构成验证决策
    if (!ok && verifyCount < ec.verifyLimit) {
      const center = await verifyCenter(http, last, res.decision, opts)
      if (center) {
        verifyCount += 1
        await opts.onStatus?.(st.verifying)
        extra = { ...extra, ...center.fields }
        fp = center.fp ?? fp
        await opts.onStatus?.(st.verified)
        deadline = Date.now() + time.timeout
        replay = true
        continue
      }
    }

    // 短信/密码二次验证:account_flow=verify 或带 biz_params 即为服务端下发的 MFA 挑战
    // (2046 响应的 biz_params 含 std_verify_flow_id/token,每轮刷新),优先走内置流程;
    // 无可用验证方式时回退 App 侧验证提示,等待服务端放行
    if (!ok && !mfaDone && (last.account_flow === fld.accountFlow || last.biz_params != null)) {
      await opts.onStatus?.(st.verifying)
      try {
        extra = { ...extra, ...await mfa(http, last, opts) }
        mfaDone = true
        deadline = Date.now() + time.timeout
      } catch (e) {
        log.warn(`二次验证不可自动完成: ${why(e)}`)
        await opts.onStatus?.(msg.appVerify)
        await sleep(time.appVerifyWait)
        replay = false
        continue
      }
      // 与官方一致:验证完成是同一轮外层轮询的重放,沿用失败轮签名;
      // 重新签名会被服务端当成新的一轮轮询,正是二次验证期间触发频控的主因
      replay = true
      continue
    }
    replay = false

    if (!ok) {
      // 频控是暂时性的(服务端明确提示稍后再试):逐次加大退避重试有限次数,不能直接判死登录
      if (code === ec.tooFrequent) {
        if (frequent >= ec.frequentLimit) err(last)
        frequent += 1
        const wait = time.pollMax * frequent
        log.warn(`check_qrconnect 触发频控,${wait}ms 后重试 ${frequent}/${ec.frequentLimit}`)
        // 退避是被服务端要求等待,不该吃掉用户扫码/验证的时间
        deadline += wait
        await sleep(wait)
        continue
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
      err(last)
    }

    // 同一状态只回调一次(轮询期间 scanned 会重复出现)
    if (last.status && last.status !== notified) {
      notified = last.status
      await opts.onStatus?.(last.status)
    }
    if (last.status === st.confirmed) return sessionOf(http, last.user_data)
    if (last.status === st.expired) err(last)
    await sleep(pace(count))
  }

  err({ timeout: time.timeout, status: last?.status })
}
