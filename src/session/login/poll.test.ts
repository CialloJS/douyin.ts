/** 二次验证回归测试:只替换 HTTP 传输,签名/表单编码/轮询逻辑走真实实现 */
import assert from 'node:assert/strict'
import test, { type TestContext } from 'node:test'
import { isErr } from '../../error.js'
import { Http } from '../http.js'
import type { Res } from '../types.js'
import { path, way } from './codes.js'
import { poll } from './poll.js'
import type { CheckData, MfaInfo } from './types.js'

interface Call {
  url: string
  body: string
}

interface Reply {
  message: string
  data: unknown
}

/** 仅替换 json():其余方法(签名、Cookie、表单)保持真实 */
class Fake extends Http {
  calls: Call[] = []
  reply: (call: Call) => Reply = () => ({ message: 'error', data: { error_code: 500 } })

  constructor () {
    super({ log: { info: () => {}, warn: () => {}, error: () => {} } })
    this.deviceId = '7000000000000000001'
    this.installId = '8000000000000000001'
  }

  override async json<T> (url: string, init: RequestInit = {}): Promise<Res<T>> {
    const call = { url, body: String(init.body ?? '') }
    this.calls.push(call)
    const data = this.reply(call) as T
    return { ok: true, status: 200, headers: new Headers(), data, text: JSON.stringify(data) }
  }
}

const param = (call: Call | undefined, key: string): string | null =>
  call ? new URLSearchParams(call.body).get(key) : null

const query = (call: Call | undefined, key: string): string | null =>
  call ? new URL(call.url).searchParams.get(key) : null

const checksOf = (http: Fake): Call[] =>
  http.calls.filter(c => c.url.includes(path.check))

/** node:test 的 MockTimers 只提供同步 tick;推进后让出事件循环,等轮询链挂上下一个定时器 */
async function advance (t: TestContext, ms: number): Promise<void> {
  t.mock.timers.tick(ms)
  await new Promise(resolve => setImmediate(resolve))
}

/** 服务端下发的二次验证挑战(2046 + biz_params) */
function challenge (verifyWay: string, mobile?: string): CheckData {
  return {
    error_code: 2046,
    account_flow: 'verify',
    encrypt_uid: 'enc-uid',
    biz_params: {
      std_verify_flow_id: 'flow-1',
      std_verify_token: 'token-1',
      std_verify_way: verifyWay,
      std_verify_scene: 'p0',
      std_verify_template: 'ato',
      std_verify_type: 'MFA',
    },
    verify_ways: [{ verify_way: verifyWay, ...(mobile ? { mobile } : {}) }],
  }
}

const confirmed: Reply = {
  message: 'success',
  data: { status: 'confirmed', error_code: 0, user_data: { user_id_str: '42' } },
}

test('短信二次验证:通过后确认轮带上 biz 参数并登录成功', async () => {
  const http = new Fake()
  const infos: MfaInfo[] = []
  const status: string[] = []
  let checks = 0
  http.reply = call => {
    if (call.url.includes(path.check)) {
      checks += 1
      return checks === 1
        ? { message: 'error', data: challenge(way.sms, '138****8888') }
        : confirmed
    }
    // 发码成功后才把短信内容交给调用方
    if (call.url.includes(path.send)) return { message: 'success', data: { mobile: '138****8888' } }
    if (call.url.includes(path.validate)) return { message: 'success', data: { ticket: 'ticket-1' } }
    return { message: 'error', data: {} }
  }

  const session = await poll(http, 'qr-token', {
    onMfa: info => {
      infos.push(info)
      return '123456'
    },
    onStatus: s => {
      status.push(s)
    },
  })

  assert.equal(session.userId, '42')
  assert.deepEqual(infos, [{ kind: 'sms', maskedMobile: '138****8888' }])
  assert.deepEqual(status, ['verifying', 'verified', 'confirmed'])

  const send = http.calls.find(c => c.url.includes(path.send))
  assert.equal(param(send, 'std_verify_way'), way.sms)
  assert.equal(param(send, 'std_verify_flow_id'), 'flow-1')
  assert.equal(param(send, 'type'), '3737')

  const validate = http.calls.find(c => c.url.includes(path.validate))
  assert.equal(param(validate, 'std_verify_way'), way.sms)
  // 验证码按 mixEncode 编码,不能明文上送
  assert.ok(param(validate, 'code'))
  assert.notEqual(param(validate, 'code'), '123456')

  // 通过后的确认轮必须回填 biz 参数,否则服务端仍返回 2046
  const first = checksOf(http)[0]
  const confirm = checksOf(http)[1]
  assert.equal(param(confirm, 'std_verify_flow_id'), 'flow-1')
  assert.equal(param(confirm, 'std_verify_token'), 'token-1')
  assert.equal(param(confirm, 'std_verify_way'), way.sms)
  assert.equal(param(confirm, 'token'), 'qr-token')

  // 确认轮是同一轮轮询的重放:沿用失败轮签名,只重算 a_bogus
  assert.equal(query(confirm, 'sign'), query(first, 'sign'))
  assert.equal(query(confirm, 'ts'), query(first, 'ts'))
  assert.notEqual(query(confirm, 'a_bogus'), query(first, 'a_bogus'))
})

test('密码二次验证:密码按 xor5+hex 编码后提交,不发短信', async () => {
  const http = new Fake()
  let checks = 0
  http.reply = call => {
    if (call.url.includes(path.check)) {
      checks += 1
      return checks === 1
        ? { message: 'error', data: challenge(way.password) }
        : confirmed
    }
    if (call.url.includes(path.password)) return { message: 'success', data: { ticket: 'ticket-1' } }
    return { message: 'error', data: {} }
  }

  const session = await poll(http, 'qr-token', { onMfa: () => '123456' })

  assert.equal(session.userId, '42')
  assert.equal(http.calls.some(c => c.url.includes(path.send)), false)

  const pwd = http.calls.find(c => c.url.includes(path.password))
  assert.equal(param(pwd, 'password'), '343736313033')
  assert.equal(param(pwd, 'mix_mode'), '1')
  assert.equal(param(pwd, 'type'), null)
  assert.equal(param(pwd, 'std_verify_way'), way.password)

  assert.equal(param(checksOf(http)[1], 'std_verify_flow_id'), 'flow-1')
  assert.equal(param(checksOf(http)[1], 'std_verify_way'), way.password)
})

test('频控 error_code=7 退避后继续轮询,不再直接判死登录', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const http = new Fake()
  let checks = 0
  http.reply = () => {
    checks += 1
    return checks === 1
      ? { message: 'error', data: { error_code: 7, description: '访问太频繁，请稍后再试' } }
      : confirmed
  }

  const running = poll(http, 'qr-token', {})
  await advance(t, 0)
  await advance(t, 5000)

  const session = await running
  assert.equal(session.userId, '42')
  assert.equal(checks, 2)
})

test('频控超过重试上限:抛出服务端响应且不再带 fatal 标记', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const http = new Fake()
  http.reply = () => ({
    message: 'error',
    data: { error_code: 7, description: '访问太频繁，请稍后再试' },
  })

  // 先挂上拒绝处理,避免假定时器推进期间出现未处理拒绝
  const failed = poll(http, 'qr-token', {}).then(
    () => undefined,
    (e: unknown) => e,
  )
  await advance(t, 0)
  await advance(t, 5000)
  await advance(t, 10_000)
  await advance(t, 15_000)

  const e = await failed
  assert.ok(isErr(e))
  const data = e.data as { error_code?: number; fatal?: boolean }
  assert.equal(data.error_code, 7)
  assert.equal(data.fatal, undefined)
  assert.equal(http.calls.length, 4)
})
