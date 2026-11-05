/** 轻量日志：零依赖，输出收敛到 console；调用方可注入同形态实现替换 */
import type { Log } from '../types.js'

const GRAY = '\x1b[90m'
const CYAN = '\x1b[36m'
const YELLOW = '\x1b[33m'
const RED = '\x1b[31m'
const RESET = '\x1b[0m'

const pad = (n: number): string => String(n).padStart(2, '0')

function stamp (): string {
  const now = new Date()
  return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`
}

/** quiet 整体关停输出；tag 区分多实例来源 */
export function createLog (opts: { tag?: string; quiet?: boolean } = {}): Log {
  if (opts.quiet) return { info: () => {}, warn: () => {}, error: () => {} }
  const head = opts.tag ? `${GRAY}[${opts.tag}]${RESET} ` : ''
  const line = (color: string, level: string, msg: string): string =>
    `${GRAY}${stamp()}${RESET} ${head}${color}${level}${RESET} ${msg}`
  return {
    info: msg => console.info(line(CYAN, 'info', msg)),
    warn: msg => console.warn(line(YELLOW, 'warn', msg)),
    error: msg => console.error(line(RED, 'error', msg)),
  }
}
