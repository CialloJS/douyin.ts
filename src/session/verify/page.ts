/** 验证页 HTML:注入启动数据与桥接脚本,React 由本地静态路由提供 */
import { im } from '../sign/const.js'
import type { Prepared } from './types.js'
import { escapeHtml, safeJson } from './json.js'
import { bridge } from './bridge.js'

export function page (prep: Prepared, token: string): string {
  // 页面侧只认 captchaScriptUrls/captchaOptions/scriptUrl 几个字段,按 mode 只注入对应形态
  const boot: Record<string, unknown> = {
    mode: prep.mode,
    config: prep.config,
    fp: prep.fp,
    sessionToken: token,
    deviceId: prep.deviceId,
    aid: prep.aid,
    host: prep.host,
    appName: prep.appName,
  }
  if (prep.mode === 'verify-center') {
    boot['captchaScriptUrls'] = prep.scripts
    boot['captchaOptions'] = prep.options
  } else if (prep.script) {
    boot['scriptUrl'] = prep.script
  }
  const quoted = encodeURIComponent(token)
  return shell(
    '抖音登录安全验证',
    `
    <div id="app"><div class="loading">正在加载抖音安全验证…</div></div>
    <script src="/react.js?token=${quoted}"></script>
    <script src="/react-dom.js?token=${quoted}"></script>
    <script>window.__LOGIN_VERIFY__=${safeJson(boot)};</script>
    <script>${bridge(im.version)}</script>
    <script>window.startDouyinVerification();</script>
  `,
  )
}

function shell (title: string, body: string): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:#f5f5f5;color:#161823;font-family:system-ui,-apple-system,sans-serif;display:grid;place-items:center}.card{width:min(420px,calc(100vw - 32px));background:white;border-radius:16px;padding:28px;box-shadow:0 12px 48px #0001}.card h1{font-size:22px;margin:0 0 12px}.card p,.loading{color:#666}#app{min-width:min(420px,calc(100vw - 32px))}
  </style></head><body>${body}</body></html>`
}
