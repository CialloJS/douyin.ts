/** 启动本地验证页并等待用户完成官方安全验证 */
import { randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import { SdkError } from '../../error.js'
import { time } from '../login/codes.js'
import type { Http } from '../http.js'
import type { Decision, Hooks, Outcome } from './types.js'
import { loadReact } from './sdk.js'
import { prepare } from './prepare.js'
import { route, sendJson } from './route.js'

export async function verify (http: Http, descriptor: Decision, hooks: Hooks = {}): Promise<Outcome> {
  const timeoutMs = hooks.timeoutMs ?? time.verify
  const [react, reactDom] = await loadReact()
  const prep = await prepare(http, descriptor, hooks)

  return new Promise<Outcome>((resolve, reject) => {
    let finished = false
    const token = randomUUID()
    const finish = (error?: Error, outcome?: Outcome): void => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      server.close(() => (error ? reject(error) : resolve(outcome ?? { fields: {} })))
    }
    const server = createServer((request, response) => {
      void route(request, response, { http, prep, react, reactDom, token, finish })
        .catch((error: unknown) => {
          sendJson(response, 500, { error: error instanceof Error ? error.message : String(error) })
        })
    })
    server.once('error', error => finish(error))
    const timer = setTimeout(() => finish(new SdkError({ timeout: timeoutMs })), timeoutMs)
    timer.unref()
    server.listen(0, '0.0.0.0', () => {
      const address = server.address()
      if (typeof address !== 'object' || address === null) {
        finish(new SdkError({ address }))
        return
      }
      const url = `http://127.0.0.1:${address.port}/?token=${encodeURIComponent(token)}`
      http.log.info(`登录安全验证页: ${url}`)
      hooks.onUrl?.(url)
    })
  })
}
