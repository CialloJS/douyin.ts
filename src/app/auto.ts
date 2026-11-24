/** 滑块自动通过：用 decision 声明的真机形态跑官方 SDK；桌面/手机浏览器形态与 App 通道矛盾会 5014 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Browser, BrowserContext, Page } from 'playwright-core'
import { createLog } from '../session/log.js'
import type { Dev } from './types.js'

const log = createLog({ tag: 'auto' })

export interface AutoInput {
  /** 本机验证页：走 127.0.0.1，避免被系统防火墙拦 */
  url: string
  dev: Dev
  /** 服务端已通过/超时/关闭时尽快退出 */
  done: () => boolean
}

interface Question {
  url1?: string
  url2?: string
  tip_y?: number
}

interface GetRes {
  code?: number
  message?: string
  data?: { question?: Question }
}

interface State {
  get: GetRes | null
  verify: string
}

interface Geo {
  bgW: number
  bgH: number
  pcW: number
  pcH: number
  pieceOffX: number
  pieceOffY: number
  btnX: number
  btnY: number
}

interface Gap {
  drag: number
  score: number
  gapLeft?: number
  gapTop?: number
  bgNatW?: number
  /** 拼图原图宽，用于核对几何换算 */
  pcNat?: number
  /** 粗扫前几名（原图 x / y / 得分），区分真缺口与 decoy */
  top?: Array<[number, number, number]>
  /** 暗剪影得分与次优（页面内不能打日志，带回 Node 侧打印） */
  dark?: number
  second?: number
  /** 页面内产生的说明，回 Node 侧打印 */
  note?: string
  error?: string
}

interface MatchIn {
  bgB64: string
  pcB64: string
  tipY: number
  bgW: number
  pieceOffX: number
  /** 拼图当前纵向位置（显示像素）；横滑块的缺口与拼图同高，比 tip_y 更准 */
  pieceOffY: number
}

/** 页面侧最小 DOM 类型：本项目 lib 不含 DOM，只声明算法体真正用到的成员 */
interface Box {
  x: number
  y: number
  width: number
  height: number
}

interface El {
  getBoundingClientRect(): Box
}

interface Bitmap {
  width: number
  height: number
}

interface Ctx {
  drawImage(b: Bitmap, x: number, y: number): void
  getImageData(x: number, y: number, w: number, h: number): { data: Uint8ClampedArray }
}

interface Canvas {
  width: number
  height: number
  getContext(id: '2d', opts?: { willReadFrequently?: boolean }): Ctx | null
}

interface Doc {
  createElement(tag: 'canvas'): Canvas
  querySelector(sel: string): El | null
}

interface Win {
  document: Doc
  atob(s: string): string
  createImageBitmap(b: unknown): Promise<Bitmap>
  Blob: new (parts: unknown[]) => unknown
}

/** ok 通过；cool 被 5014 频控/环境拦（需断流冷却）；fail 其他失败（换题重试） */
export type Step = 'ok' | 'fail' | 'cool'

/** DY_DUMP_GAP 落图序号：一进程多题时会话并存，固定文件名会互相覆盖 */
let dumpN = 0
/** 载荷落盘序号，同样按进程递增避免覆盖 */
let payN = 0

/** 排查用：SDK 把明文 JSON 交给加密函数，钩住 stringify 就能看到它采集了哪些 env 与轨迹 */
const PAYLOAD_HOOK = `globalThis.__SJ = []; (() => {
  const s = JSON.stringify, out = globalThis.__SJ;
  JSON.stringify = function () {
    const r = s.apply(this, arguments);
    try { if (typeof r === 'string' && r.length > 500) out.push(r) } catch (e) {}
    return r;
  };
})();`

function dumpDir (): string {
  const d = process.env.DY_DUMP_GAP
  return d && d !== '1' ? d : join(tmpdir(), 'dy-gap')
}

async function dumpPayload (page: Page): Promise<void> {
  const list = await page.evaluate(() => (globalThis as unknown as { __SJ?: string[] }).__SJ ?? [])
    .catch(() => [] as string[])
  if (!list.length) {
    log.warn('没拿到载荷：SDK 未走 JSON.stringify')
    return
  }
  const dir = dumpDir()
  mkdirSync(dir, { recursive: true })
  const no = ++payN
  list.forEach((s, i) => writeFileSync(join(dir, `payload-${no}-${i}.json`), s))
  log.info(`载荷已落盘 ${list.length} 条 → ${dir}`)
}

function sleep (ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * 设备 resolution + dpi → 浏览器视口与 DPR。
 * 必须用注册时上报的分辨率：滑块通道若声明另一套整屏尺寸，与登录/注册参数矛盾会被判 5014。
 */
function viewport (dev: Dev): { width: number; height: number; dpr: number } {
  const m = /^(\d+)\s*[*x]\s*(\d+)$/i.exec(dev.resolution)
  const dpr = Math.max(1, dev.dpi / 160)
  const w = m ? Number(m[1]) : 1272
  const h = m ? Number(m[2]) : 2800
  return {
    width: Math.max(320, Math.min(480, Math.round(w / dpr))),
    height: Math.max(560, Math.min(900, Math.round(h / dpr))),
    dpr: Math.round(dpr * 100) / 100,
  }
}

/** 必须是带 wv 的 Android WebView 形态：无 wv 的普通手机/桌面浏览器一律被 bdturing 判 5014 */
function webViewUa (dev: Dev): string {
  return `Mozilla/5.0 (Linux; Android ${dev.osVersion}; ${dev.deviceType} Build/${dev.build}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36`
}

async function launch (pw: typeof import('playwright-core'), dev: Dev): Promise<Browser | null> {
  const vp = viewport(dev)
  const headless = process.env.DY_SLIDE_HEADLESS === '1'
  for (const channel of ['msedge', 'chrome', undefined] as const) {
    try {
      const browser = await pw.chromium.launch({
        channel,
        headless,
        args: [
          '--disable-blink-features=AutomationControlled',
          // 真实窗口要和模拟视口一样大：SDK 会比对 outerWidth-innerWidth，
          // 桌面大窗口套移动视口必被当成模拟环境
          `--window-size=${vp.width},${vp.height}`,
        ],
      })
      log.info(`浏览器已启动（${channel ?? '自带 chromium'}，headless=${headless}）`)
      return browser
    } catch (e) {
      log.warn(`启动 ${channel ?? 'chromium'} 失败: ${String(e).slice(0, 140)}`)
    }
  }
  return null
}

/**
 * 拟人横向位移序列：真机触摸约 60Hz 采样、整段 0.8~1.5s，点数 50+。
 * 点太少太快（原来 20~30 点/300ms）会被 bdturing 判成机器，直接回 5014。
 */
function humanTrack (dx: number): number[] {
  const steps = 52 + Math.floor(Math.random() * 38)
  const track: number[] = []
  // 真人在接近缺口时会先冲过一点再回退
  const over = Math.random() < 0.7 ? 1 + Math.random() * 2.5 : 0
  const total = dx + over
  let cur = 0
  for (let i = 1; i <= steps; i++) {
    const p = i / steps
    const target = total * (1 - Math.pow(1 - p, 3))
    const jitter = (Math.random() * 2 - 1) * (p < 0.9 ? 0.9 : 0.25)
    const next = Math.max(cur, target + jitter)
    if (next - cur < 0.5) continue
    track.push(Number((next - cur).toFixed(2)))
    cur = next
  }
  if (over > 0) {
    track.push(Number((-over).toFixed(2)))
    cur -= over
  }
  track.push(Number((dx - cur).toFixed(2)))
  return track
}

/** 返回首个真值结果；超时为 null。用返回值而非闭包赋值，避免 TS 认为外部变量恒为初始值 */
async function waitFor<T> (probe: () => T | null | Promise<T | null>, timeoutMs: number, step = 200): Promise<T | null> {
  const end = Date.now() + timeoutMs
  while (Date.now() < end) {
    try {
      const v = await probe()
      if (v) return v
    } catch {
      // 页面跳转中 querySelector / 定位可能抛错
    }
    await sleep(step)
  }
  return null
}

/** 读滑块几何：拖动前必须现量，SDK 的入场动画会让几秒前的 rect 失效 */
function geo (page: Page): Promise<Geo | null> {
  return page.evaluate((): Geo | null => {
    const doc = (globalThis as unknown as Win).document
    const bg = doc.querySelector('.captcha-verify-image')
    const pc = doc.querySelector('#captcha-verify_img_slide')
    const btn = doc.querySelector('.captcha-slider-btn')
    if (!bg || !pc || !btn) return null
    const r1 = bg.getBoundingClientRect()
    const r2 = pc.getBoundingClientRect()
    const r3 = btn.getBoundingClientRect()
    return {
      bgW: Math.round(r1.width),
      bgH: Math.round(r1.height),
      pcW: Math.round(r2.width),
      pcH: Math.round(r2.height),
      pieceOffX: r2.x - r1.x,
      pieceOffY: r2.y - r1.y,
      btnX: r3.x + r3.width / 2,
      btnY: r3.y + r3.height / 2,
    }
  })
}

/**
 * 页面内模板匹配：灰度零均值 NCC。
 * 必须在原图分辨率上算——显示尺寸把 552 缩到 363 后，真缺口与旁边假缺口的分数差会被抹平。
 * 几何依据：移动端 .verify-image 宽 2.76em、拼图 0.55em，拼图纵向位置 = tip_y/100 em，
 * 换算回原图坐标就是 tip_y*bgNatW/276。
 */
async function matchFn (a: MatchIn): Promise<Gap> {
  const g = globalThis as unknown as Win
  const doc = g.document
  const load = async (b64: string): Promise<{ w: number; h: number; d: Uint8ClampedArray }> => {
    const bin = g.atob(b64)
    const u8 = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
    const bmp = await g.createImageBitmap(new g.Blob([u8]))
    const cv = doc.createElement('canvas')
    cv.width = bmp.width
    cv.height = bmp.height
    const c2 = cv.getContext('2d', { willReadFrequently: true })
    if (!c2) throw new Error('canvas 2d 不可用')
    c2.drawImage(bmp, 0, 0)
    return { w: cv.width, h: cv.height, d: c2.getImageData(0, 0, cv.width, cv.height).data }
  }
  const bg = await load(a.bgB64)
  const pc = await load(a.pcB64)
  const BW = bg.w
  const BH = bg.h
  const PW = pc.w
  const PH = pc.h
  if (PW > BW || PH > BH) return { drag: 0, score: -1, error: '拼图比背景大' }
  // 页面上下文里没有 Node 的 log，说明文字回传由 Node 侧打印
  let note: string | undefined

  // 拼图有效内容 = alpha>40 的像素，同时取灰度
  const pGray = new Float32Array(PW * PH)
  let minX = PW
  let maxX = -1
  let minY = PH
  let maxY = -1
  for (let y = 0; y < PH; y++) {
    for (let x = 0; x < PW; x++) {
      const i = (y * PW + x) * 4
      pGray[y * PW + x] = 0.299 * pc.d[i] + 0.587 * pc.d[i + 1] + 0.114 * pc.d[i + 2]
      if (pc.d[i + 3] > 40) {
        if (x < minX) minX = x
        if (x > maxX) maxX = x
        if (y < minY) minY = y
        if (y > maxY) maxY = y
      }
    }
  }
  if (maxX < 0) return { drag: 0, score: -1, error: '拼图 alpha 为空' }

  const oxs: number[] = []
  const oys: number[] = []
  for (let y = minY; y <= maxY; y++) {
    for (let x = minX; x <= maxX; x++) {
      if (pc.d[(y * PW + x) * 4 + 3] <= 40) continue
      oxs.push(x)
      oys.push(y)
    }
  }
  const n = oxs.length

  // 背景缺口是一块暗色遮罩（洞内内容被整块替换成暗块），拼图却是亮色内容+浅描边：
  // 逐像素相关在洞上必然失配（实测真洞 0.36、假洞 0.52），只能按 alpha 形状与暗块算 IoU。
  // 同题常出现「一个真洞 + 一个更小的假洞」，尺寸差由 IoU 直接拉开。
  const maskW = maxX - minX + 1
  const maskH = maxY - minY + 1
  const dark = new Uint8Array(BW * BH)
  for (let j = 0, i = 0; j < dark.length; j++, i += 4) {
    const r = bg.d[i]
    const g2 = bg.d[i + 1]
    const b2 = bg.d[i + 2]
    const mx = r > g2 ? (r > b2 ? r : b2) : (g2 > b2 ? g2 : b2)
    const mn = r < g2 ? (r < b2 ? r : b2) : (g2 < b2 ? g2 : b2)
    if (mx < 135 && mx - mn < 95) dark[j] = 1
  }
  const bGray = new Float32Array(BW * BH)
  for (let j = 0, i = 0; j < bGray.length; j++, i += 4) {
    bGray[j] = 0.299 * bg.d[i] + 0.587 * bg.d[i + 1] + 0.114 * bg.d[i + 2]
  }
  // 内容相关：洞是半透明暗遮罩，整体压暗属于线性缩放，不会改变零均值相关系数，
  // 所以同一道题里「真洞」的内容与拼图内容相关性明显更高；step 只影响采样密度
  const makeScorer = (step: number): ((x: number, y: number) => number) => {
    const idx: number[] = []
    for (let k = 0; k < n; k += step) idx.push(k)
    let s0 = 0
    for (const k of idx) s0 += pGray[oys[k] * PW + oxs[k]]
    const m0 = s0 / idx.length
    const v0 = new Float64Array(idx.length)
    let n0 = 0
    for (let j = 0; j < idx.length; j++) {
      const v = pGray[oys[idx[j]] * PW + oxs[idx[j]]] - m0
      v0[j] = v
      n0 += v * v
    }
    n0 = Math.sqrt(n0) || 1
    return (x: number, y: number): number => {
      let sum = 0
      let sum2 = 0
      for (let j = 0; j < idx.length; j++) {
        const v = bGray[(y + oys[idx[j]]) * BW + (x + oxs[idx[j]])]
        sum += v
        sum2 += v * v
      }
      const cnt = idx.length
      const mean = sum / cnt
      const varB = sum2 - cnt * mean * mean
      if (varB <= 1e-3) return -2
      let dot = 0
      for (let j = 0; j < idx.length; j++) {
        dot += v0[j] * (bGray[(y + oys[idx[j]]) * BW + (x + oxs[idx[j]])] - mean)
      }
      return dot / (n0 * Math.sqrt(varB))
    }
  }
  const nccOf = makeScorer(2)
  // 洞是与拼图同形的一块纯暗遮罩，但常和深色山体/阴影连成一大块，用整块面积当分母
  // 会把真洞稀释（盾形题实测只有 0.36）。改为在候选块附近滑动拼图形状，只统计窗口
  // 内的暗像素，并用「遮罩内方差极低、山体有纹理」来区分二者。
  const W1 = BW + 1
  const ss = new Float64Array(W1 * (BH + 1))
  const sq = new Float64Array(W1 * (BH + 1))
  const sd = new Int32Array(W1 * (BH + 1))
  for (let y = 0; y < BH; y++) {
    let row = 0
    let row2 = 0
    let rowd = 0
    for (let x = 0; x < BW; x++) {
      const v = bGray[y * BW + x]
      row += v
      row2 += v * v
      rowd += dark[y * BW + x]
      ss[(y + 1) * W1 + (x + 1)] = ss[y * W1 + (x + 1)] + row
      sq[(y + 1) * W1 + (x + 1)] = sq[y * W1 + (x + 1)] + row2
      sd[(y + 1) * W1 + (x + 1)] = sd[y * W1 + (x + 1)] + rowd
    }
  }
  const area = (p: Float64Array | Int32Array, x: number, y: number): number =>
    p[(y + maskH) * W1 + x + maskW] - p[y * W1 + x + maskW] - p[(y + maskH) * W1 + x] + p[y * W1 + x]
  const sample: number[] = []
  for (let k = 0; k < n; k += 3) sample.push(k)
  const cnt = maskW * maskH
  /** 拼图内容 bbox 落在 (bx,by) 时与暗块的重合度；0 表示该位置不可能 */
  const shape = (bx: number, by: number): number => {
    const wd = area(sd, bx, by)
    if (wd < n * 0.5 || wd > n * 2.4) return 0
    const mean = area(ss, bx, by) / cnt
    if (mean > 130) return 0
    const std = Math.sqrt(Math.max(0, area(sq, bx, by) / cnt - mean * mean))
    const flat = 1 - std / 18
    if (flat <= 0) return 0
    let hit = 0
    for (const k of sample) {
      if (dark[(by + oys[k] - minY) * BW + bx + oxs[k] - minX]) hit++
    }
    const inter = (hit * n) / sample.length
    return (inter / (n + wd - inter)) * flat
  }

  // 缺口是半透明暗剪影：用大核局部均值求「比周围暗」的强度，形状内均值最强处即真洞。
  // 连通域法会被天空/山体撑大而失效（实测盾形/星形题 hits 全被过滤），积分图逐位置求值不受影响。
  const kk = 41
  const kh = kk >> 1
  const diff = new Float32Array(BW * BH)
  for (let y = 0; y < BH; y++) {
    const ya = Math.max(0, y - kh)
    const yb = Math.min(BH, y + kh + 1)
    for (let x = 0; x < BW; x++) {
      const xa = Math.max(0, x - kh)
      const xb = Math.min(BW, x + kh + 1)
      const s = ss[yb * W1 + xb] - ss[ya * W1 + xb] - ss[yb * W1 + xa] + ss[ya * W1 + xa]
      diff[y * BW + x] = s / ((yb - ya) * (xb - xa)) - bGray[y * BW + x]
    }
  }
  const dOff: number[] = []
  for (let k = 0; k < n; k += 3) dOff.push(oys[k] * BW + oxs[k])
  const dN = dOff.length
  const darkMean = (x: number, y: number): number => {
    const base = y * BW + x
    let sum = 0
    for (let j = 0; j < dN; j++) sum += diff[base + dOff[j]]
    return sum / dN
  }
  // 粗扫步长 4 只需定位到洞，精扫再补齐像素级；
  // 次优必须换一个洞（距离 >40），否则取到的是真洞旁边的点，比值判断永远不成立
  const cand: Array<[number, number, number]> = []
  for (let y = 0; y + PH <= BH; y += 4) {
    for (let x = 0; x + PW <= BW; x += 4) cand.push([x, y, darkMean(x, y)])
  }
  cand.sort((p, q) => q[2] - p[2])
  let dBest = -1e9
  let d2 = -1e9
  let dX = 0
  let dY = 0
  for (const [x, y, v] of cand) {
    if (dBest < -1e8) {
      dBest = v
      dX = x
      dY = y
    } else if (Math.abs(x - dX) > 40 || Math.abs(y - dY) > 40) {
      d2 = v
      break
    }
  }
  if (dBest < -1e8) return { drag: 0, score: -1, error: '暗剪影无候选' }
  // 精扫用全像素采样：粗扫 step4 + step3 抽样最优点可偏 10px（实测 238 vs 真值 248），
  // 窗口必须盖住这个偏差，否则精扫只能收敛到错误位置
  const dOffF: number[] = []
  for (let k = 0; k < n; k++) dOffF.push(oys[k] * BW + oxs[k])
  const darkFull = (x: number, y: number): number => {
    const base = y * BW + x
    let sum = 0
    for (let j = 0; j < dOffF.length; j++) sum += diff[base + dOffF[j]]
    return sum / dOffF.length
  }
  for (let y = Math.max(0, dY - 12); y <= Math.min(BH - PH, dY + 12); y++) {
    for (let x = Math.max(0, dX - 12); x <= Math.min(BW - PW, dX + 12); x++) {
      const v = darkFull(x, y)
      if (v > dBest) {
        dBest = v
        dX = x
        dY = y
      }
    }
  }
  // 真洞比次优洞明显更暗（图片题实测 22 vs 9）；差得不够就交给内容相关
  if (dBest > 6 && dBest > d2 * 1.35) {
    return {
      drag: dX * (a.bgW / BW) - a.pieceOffX,
      score: dBest,
      gapLeft: dX * (a.bgW / BW),
      gapTop: dY,
      bgNatW: BW,
      pcNat: PW,
      dark: dBest,
      second: d2,
      top: [[dX, dY, dBest]],
    }
  }

  const seen = new Uint8Array(BW * BH)
  const cells: number[] = []
  const hits: Array<[number, number, number]> = []
  for (let s = 0; s < dark.length; s++) {
    if (!dark[s] || seen[s]) continue
    cells.length = 0
    seen[s] = 1
    cells.push(s)
    let cx0 = BW
    let cx1 = -1
    let cy0 = BH
    let cy1 = -1
    for (let h = 0; h < cells.length; h++) {
      const p = cells[h]
      const x = p % BW
      const y = Math.floor(p / BW)
      if (x < cx0) cx0 = x
      if (x > cx1) cx1 = x
      if (y < cy0) cy0 = y
      if (y > cy1) cy1 = y
      if (x > 0 && dark[p - 1] && !seen[p - 1]) { seen[p - 1] = 1; cells.push(p - 1) }
      if (x + 1 < BW && dark[p + 1] && !seen[p + 1]) { seen[p + 1] = 1; cells.push(p + 1) }
      if (p >= BW && dark[p - BW] && !seen[p - BW]) { seen[p - BW] = 1; cells.push(p - BW) }
      if (p + BW < dark.length && dark[p + BW] && !seen[p + BW]) { seen[p + BW] = 1; cells.push(p + BW) }
    }
    const cw = cx1 - cx0 + 1
    const ch = cy1 - cy0 + 1
    // 面积与长宽都要和拼图对得上，滤掉树影/楼体等顺带被判暗的大块
    if (cells.length < n * 0.15) continue
    if (cw < maskW * 0.45 || cw > maskW * 3.2 || ch < maskH * 0.45 || ch > maskH * 3.2) continue
    // 洞可能被旁边的山体撑大，在块附近粗扫 3px 找最佳对位，再局部精扫
    const xa = Math.max(0, cx0 - maskW + 1)
    const xb = Math.min(BW - maskW, cx1)
    const ya = Math.max(0, cy0 - maskH + 1)
    const yb = Math.min(BH - maskH, cy1)
    let best = 0
    let bx0 = xa
    let by0 = ya
    for (let by = ya; by <= yb; by += 3) {
      for (let bx = xa; bx <= xb; bx += 3) {
        const v = shape(bx, by)
        if (v > best) {
          best = v
          bx0 = bx
          by0 = by
        }
      }
    }
    if (best <= 0) continue
    for (let by = Math.max(ya, by0 - 3); by <= Math.min(yb, by0 + 3); by++) {
      for (let bx = Math.max(xa, bx0 - 3); bx <= Math.min(xb, bx0 + 3); bx++) {
        const v = shape(bx, by)
        if (v > best) {
          best = v
          bx0 = bx
          by0 = by
        }
      }
    }
    hits.push([bx0, by0, best])
  }
  hits.sort((p, q) => q[2] - p[2])
  // 盾形题常画两个同形暗洞，形状 IoU 几乎并列（实测 0.86 / 0.85）；此时只有洞内内容
  // 与拼图内容的相关性能裁决，压暗是线性缩放，不影响零均值相关系数
  if (hits.length && hits[0][2] >= 0.6) {
    const pool = hits.filter(([, , s]) => s >= hits[0][2] - 0.08).slice(0, 5)
    let pick = pool[0]
    if (pool.length > 1) {
      let best = -2
      for (const h of pool) {
        const v = nccOf(h[0], h[1])
        if (v > best) {
          best = v
          pick = h
        }
      }
      note = `同形候选 ${pool.length} 个，按内容相关裁决 x=${pick[0]} ncc=${best.toFixed(3)}`
    }
    const [gx, gy, iou] = pick
    return {
      drag: gx * (a.bgW / BW) - a.pieceOffX,
      score: iou,
      gapLeft: gx * (a.bgW / BW),
      gapTop: gy,
      bgNatW: BW,
      pcNat: PW,
      note,
      top: hits.slice(0, 5),
    }
  }

  // 纵向锚点：拼图当前就在缺口的纵坐标上（横滑块只横向移动），换算回原图即为候选 y。
  // tip_y 只是声明的整数百分比，实测与拼图实际位置有偏差，仅作兜底。
  const yTip = Number.isFinite(a.tipY) ? (a.tipY / 100) * (BW / 2.76) : NaN
  const yPiece = a.bgW > 0 ? (a.pieceOffY * BW) / a.bgW : NaN
  const clampY = (v: number): number => Math.max(0, Math.min(BH - PH, Math.round(v)))
  const window = (anchor: number, span: number): number[] => {
    const out: number[] = []
    const y0 = clampY(anchor)
    for (let d = -span; d <= span; d++) {
      const y = y0 + d
      if (y >= 0 && y + PH <= BH) out.push(y)
    }
    return out
  }
  let ys = Number.isFinite(yPiece) ? window(yPiece, 24) : []
  if (!ys.length && Number.isFinite(yTip)) ys = window(yTip, Math.round(PH))
  if (!ys.length) {
    for (let y = 0; y + PH <= BH; y += 2) ys.push(y)
  }
  // 并列时的纵向参考：拼图实际位置优先
  const anchorY = Number.isFinite(yPiece) ? yPiece : yTip

  const coarse = makeScorer(3)
  let bestX = 0
  let bestY = ys[0] ?? 0
  let bestScore = -2
  const cands: Array<[number, number, number]> = []
  for (const y of ys) {
    for (let x = 0; x + PW <= BW; x++) {
      const s = coarse(x, y)
      cands.push([x, y, s])
      if (s > bestScore) {
        bestScore = s
        bestX = x
        bestY = y
      }
    }
  }
  cands.sort((p, q) => q[2] - p[2])
  // 粗扫相邻 x 分数很接近，直接取前 5 会全挤在同一个缺口上；按拼图尺寸做非极大值抑制
  const top: Array<[number, number, number]> = []
  for (const c of cands) {
    if (top.every(([x, y]) => Math.abs(x - c[0]) > PW * 0.6 || Math.abs(y - c[1]) > PH * 0.6)) top.push(c)
    if (top.length >= 5) break
  }
  // 分数并列：可能是「真洞 + 假洞」两处。粗扫 3px 采样噪声大，改用全像素采样重算内容相关，
  // 洞是半透明暗遮罩、整体压暗是线性缩放，零均值相关不受影响，真洞得分更高。
  const near = top.filter(([, , s]) => s >= bestScore - 0.05)
  if (near.length > 1) {
    let pick = near[0]
    let best = -2
    for (const c of near) {
      const v = nccOf(c[0], c[1])
      if (v > best) {
        best = v
        pick = c
      }
    }
    note = `并列候选 ${near.length} 个，按内容相关裁决 x=${pick[0]} ncc=${best.toFixed(3)}`
    bestX = pick[0]
    bestY = pick[1]
    bestScore = pick[2]
  } else if (Number.isFinite(anchorY)) {
    // 同一缺口上下偏移的重复命中，取纵向更贴近拼图位置的那个
    const same = top.filter(([, , s]) => s >= bestScore - 0.02)
    let pick: [number, number, number] | null = null
    for (const c of same) {
      if (!pick || Math.abs(c[1] - anchorY) < Math.abs(pick[1] - anchorY)) pick = c
    }
    if (pick) {
      bestX = pick[0]
      bestY = pick[1]
      bestScore = pick[2]
    }
  }
  // 精扫用全像素采样独立取优：粗扫 3px 网格会把最佳 x 限制在 ±8 内，实测偏差可达 5px；
  // y 同理（粗扫 3px 采样噪声会把 y 拉偏 10px 以上，进而带偏 x），窗口放宽到 ±10
  const fine = makeScorer(1)
  const x0 = Math.max(0, bestX - 8)
  const x1 = Math.min(BW - PW, bestX + 8)
  const y0 = Math.max(0, bestY - 10)
  const y1 = Math.min(BH - PH, bestY + 10)
  let fx = bestX
  let fy = bestY
  let fs = -2
  for (let y = y0; y <= y1; y++) {
    for (let x = x0; x <= x1; x++) {
      const s = fine(x, y)
      if (s > fs) {
        fs = s
        fx = x
        fy = y
      }
    }
  }
  bestX = fx
  bestY = fy
  bestScore = fs

  const gapLeft = bestX * (a.bgW / BW)
  return {
    drag: gapLeft - a.pieceOffX,
    score: bestScore,
    gapLeft,
    gapTop: bestY,
    bgNatW: BW,
    pcNat: PW,
    note,
    top,
  }
}

/** 下载题目图 + 求缺口；图片是 CDN 直链，必须走 context.request 才能复用页面 UA */
async function match (page: Page, ctx: BrowserContext, q: Question, g: Geo): Promise<Gap> {
  if (!q.url1 || !q.url2) return { drag: 0, score: -1, error: '题目图片地址缺失' }
  try {
    const [a, b] = await Promise.all([
      ctx.request.get(q.url1, { timeout: 20000 }),
      ctx.request.get(q.url2, { timeout: 20000 }),
    ])
    const bgB64 = (await a.body()).toString('base64')
    const pcB64 = (await b.body()).toString('base64')
    // 排查用：落原图，肉眼确认真缺口与拼图内容是否可匹配；带序号避免多题互相覆盖
    if (process.env.DY_DUMP_GAP) {
      const dir = process.env.DY_DUMP_GAP === '1' ? join(tmpdir(), 'dy-gap') : process.env.DY_DUMP_GAP
      mkdirSync(dir, { recursive: true })
      const no = ++dumpN
      writeFileSync(join(dir, `bg-${no}.png`), Buffer.from(bgB64, 'base64'))
      writeFileSync(join(dir, `pc-${no}.png`), Buffer.from(pcB64, 'base64'))
    }
    const gap = await page.evaluate(matchFn, {
      bgB64,
      pcB64,
      tipY: Number(q.tip_y ?? NaN),
      bgW: g.bgW,
      pieceOffX: g.pieceOffX,
      pieceOffY: g.pieceOffY,
    })
    if (gap.dark != null) {
      const natX = (gap.gapLeft ?? 0) * ((gap.bgNatW ?? 0) / Math.max(1, g.bgW))
      log.info(`暗剪影命中 原图x=${natX.toFixed(0)} y=${gap.gapTop ?? -1} 暗度=${gap.dark.toFixed(1)} 次优=${(gap.second ?? 0).toFixed(1)}`)
    } else if (gap.note) {
      log.info(gap.note)
    }
    return gap
  } catch (e) {
    return { drag: 0, score: -1, error: `下载题目图片失败: ${String(e).slice(0, 140)}` }
  }
}

/** CDP 会话只用到 send，避免为它引入 playwright 的内部类型 */
interface Cdp {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>
}

async function drag (cdp: Cdp, g: Geo, dx: number, state: State): Promise<void> {
  // 手机上不存在 hover：看到滑块后手指直接按住，中间的停顿就是人的反应时间。
  // 必须用触摸事件：UA/视口都声明 Android，mouse 事件会让 bdturing 判成模拟（5014）。
  await sleep(300 + Math.random() * 400)
  const at = (x: number, y: number): Array<Record<string, number>> => [
    { x, y, id: 1, radiusX: 8, radiusY: 8, force: 1 },
  ]
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: at(g.btnX, g.btnY) })
  // 真机按下后不会立刻移动
  await sleep(140 + Math.random() * 220)
  let cx = g.btnX
  const track = humanTrack(dx)
  for (let i = 0; i < track.length; i++) {
    cx += track[i]
    await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: at(cx, g.btnY + (Math.random() * 2 - 1)) })
    // 触摸采样 ~60Hz；人拖到中途会犹豫一下
    if (i === Math.floor(track.length * 0.55)) await sleep(40 + Math.random() * 60)
    await sleep(10 + Math.random() * 12)
  }
  await sleep(160 + Math.random() * 220)
  // render(decision) 会先做一次只有环境、没有轨迹的静默 verify，它会先返回 5014；
  // 不清掉旧结果，下面等到的就是它，真实拖动那一发会被误判
  state.verify = ''
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
}

async function attempt (ctx: BrowserContext, cdp: Cdp, page: Page, input: AutoInput, state: State): Promise<Step> {
  // 后台窗口的鼠标事件在某些环境里不带真实焦点，SDK 行为采集会缺字段
  await page.bringToFront().catch(() => undefined)
  const hasBtn = await waitFor(async () => (await page.locator('.captcha-slider-btn').count()) > 0, 30000)
  if (!hasBtn) {
    log.warn('等不到滑块按钮')
    return 'fail'
  }
  const hasImg = await waitFor(() => !!state.get?.data?.question?.url1, 20000)
  if (!hasImg) {
    // 没有题目基本是 /captcha/get 被环境/频控拦下，密集重试只会更糟
    log.warn(`没拿到题目图片: ${state.get ? JSON.stringify(state.get).slice(0, 200) : '(无 get 响应)'}`)
    return state.get ? 'cool' : 'fail'
  }
  const q = state.get?.data?.question
  if (!q) return 'fail'

  // SDK 异步采集环境指纹，立刻拖会采不全；成功样本是 get 后约 3s 才拖动
  await sleep(2000 + Math.random() * 1200)
  if (input.done()) return 'ok'
  const cur = await waitFor(async () => {
    const next = await geo(page)
    return next && next.bgW > 0 && next.bgH > 0 && next.pcW > 0 && next.pcH > 0 ? next : null
  }, 15000, 300)
  if (!cur) {
    log.warn('滑块 DOM 未渲染完')
    return 'fail'
  }
  log.info(`DOM bg=${cur.bgW}x${cur.bgH} piece=${cur.pcW}x${cur.pcH} off=(${cur.pieceOffX.toFixed(0)},${cur.pieceOffY.toFixed(0)}) 按钮=(${cur.btnX.toFixed(0)},${cur.btnY.toFixed(0)})`)

  const m = await match(page, ctx, q, cur)
  if (m.error || !Number.isFinite(m.drag)) {
    log.warn(`缺口匹配失败: ${m.error ?? 'unknown'}`)
    return 'fail'
  }
  // 匹配到拖动之间会过几十毫秒，用最新几何重算上限，避免把拼图拖出边界
  const live = (await geo(page)) ?? cur
  const maxDrag = live.bgW - live.pcW - live.pieceOffX
  const dx = Math.max(4, Math.min(Math.max(4, maxDrag), (m.gapLeft ?? 0) - live.pieceOffX))
  const natX = (m.gapLeft ?? 0) * ((m.bgNatW ?? 0) / Math.max(1, live.bgW))
  log.info(`缺口 显示x=${(m.gapLeft ?? 0).toFixed(1)} 原图x=${natX.toFixed(0)} 原图y=${m.gapTop ?? -1} tip_y=${String(q.tip_y ?? '-')} 图=${m.bgNatW ?? 0}x bgW=${live.bgW} 拼图=${m.pcNat ?? 0} 相似度=${m.score.toFixed(3)} 偏移=${live.pieceOffX.toFixed(0)} 上限=${maxDrag.toFixed(0)} → 拖动 ${dx.toFixed(1)}px`)
  if (m.top?.length) log.info(`候选 ${m.top.map(([x, y, s]) => `${x},${y}:${s.toFixed(2)}`).join(' | ')}`)
  // 只算不拖：不触发 verify，避免消耗新设备唯一一次有效判定
  if (process.env.DY_SLIDE_DRY === '1') {
    log.info('DY_SLIDE_DRY=1，跳过拖动')
    return 'fail'
  }

  await drag(cdp, live, dx, state)
  const got = await waitFor(() => input.done() || !!state.verify, 20000)
  if (input.done()) return 'ok'
  if (!got) {
    log.warn('拖动后 20 秒没等到 verify 响应')
    return 'fail'
  }
  let code = 0
  try {
    code = Number((JSON.parse(state.verify) as { code?: number }).code ?? 0)
  } catch {
    // 非 JSON 响应
  }
  if (code === 200) {
    log.info('verify 返回 200，验证通过')
    return 'ok'
  }
  if (state.verify.includes('5014')) return 'cool'
  log.warn(`verify 未通过 code=${code}`)
  return 'fail'
}

/**
 * 起有头浏览器把本机验证页跑成真机形态。
 * 真机 HAR 实测：同一 detail 下 verify 500 后可以重新 get 新题再验，直到通过；
 * 因此这里在同一决策内重开验证页换题重试（每次都是新的 captchaBody，不是重放旧验证）。
 * 5014 是设备/网络的环境判定，换题也没用，立即交回上层。
 * 返回 null 表示本模块没跑（禁用/缺依赖/无浏览器），交给手机扫码手动拖。
 */
export async function solve (input: AutoInput): Promise<Step | null> {
  if (process.env.DY_SLIDE_AUTO === '0') {
    log.info('已禁用自动过滑块（DY_SLIDE_AUTO=0）')
    return null
  }
  let pw: typeof import('playwright-core')
  try {
    pw = await import('playwright-core')
  } catch (e) {
    log.warn(`未安装 playwright-core，回落扫码模式: ${String(e).slice(0, 120)}`)
    return null
  }
  const browser = await launch(pw, input.dev)
  if (!browser) {
    log.warn('没有可用浏览器（Edge/Chrome），回落扫码模式')
    return null
  }
  const vp = viewport(input.dev)
  const ctx = await browser.newContext({
    userAgent: webViewUa(input.dev),
    viewport: { width: vp.width, height: vp.height },
    screen: { width: vp.width, height: vp.height },
    deviceScaleFactor: vp.dpr,
    isMobile: true,
    hasTouch: true,
    locale: 'zh-CN',
    timezoneId: 'Asia/Shanghai',
  })
  log.info(`视口 ${vp.width}x${vp.height}@${vp.dpr}x = 物理 ${Math.round(vp.width * vp.dpr)}x${Math.round(vp.height * vp.dpr)}（声明 ${input.dev.resolution}）`)
  const page = await ctx.newPage()
  const cdp: Cdp = await ctx.newCDPSession(page)
  // Windows 上 Chromium 把 platform 固定成 Win32、UA-CH 报桌面 Linux，UA 却声明 Android；
  // 三份身份对不上会被 bdturing 判环境不可信。这里统一走 DevTools 协议改成手机值。
  await cdp.send('Emulation.setUserAgentOverride', {
    userAgent: webViewUa(input.dev),
    acceptLanguage: 'zh-CN',
    platform: 'Linux armv8l',
    // UA-CH 也是一份对外身份：不声明 Android 时 navigator.userAgentData 仍是桌面 Linux，与 UA 矛盾
    userAgentMetadata: {
      brands: [{ brand: 'Chromium', version: '120' }, { brand: 'Google Chrome', version: '120' }, { brand: 'Not-A.Brand', version: '99' }],
      fullVersionList: [{ brand: 'Chromium', version: '120.0.6099.144' }, { brand: 'Google Chrome', version: '120.0.6099.144' }, { brand: 'Not-A.Brand', version: '99.0.0.0' }],
      fullVersion: '120.0.6099.144',
      platform: 'Android',
      platformVersion: input.dev.osVersion ?? '17.0.0',
      architecture: 'arm',
      model: input.dev.deviceType ?? 'PLC110',
      mobile: true,
      bitness: '',
      wow64: false,
    },
  })
  // tsx/esbuild 的 keepNames 会往 evaluate 函数体注入 __name，浏览器里没有这个 helper
  await page.addInitScript({ content: 'globalThis.__name = globalThis.__name || ((f) => f);' })
  // hasTouch 默认只报 1 点，真机 WebView 是 5；用 CDP 真实模拟，页面里不要再 defineProperty 覆盖
  await cdp.send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 })
  if (process.env.DY_PAYLOAD === '1') await page.addInitScript({ content: PAYLOAD_HOOK })
  const state: State = { get: null, verify: '' }
  // get 的题目与 verify 的响应是判断「有没有题、过没过」的唯一来源
  page.on('response', resp => {
    const u = resp.url()
    if (u.includes('/captcha/get')) {
      resp.json().then((v: unknown) => { state.get = v as GetRes }).catch(() => undefined)
    } else if (u.includes('/captcha/verify')) {
      resp.text().then(t => { state.verify = t }).catch(() => undefined)
    }
  })
  try {
    // 同一决策内最多换几道题：真机 500 后重新 get 新题，第二次即通过
    const ROUNDS = 3
    let step: Step = 'fail'
    for (let round = 1; round <= ROUNDS; round++) {
      // 上一轮的题目/结果不能复用，否则会把旧题当成新题拖
      state.get = null
      state.verify = ''
      log.info(`打开验证页（第 ${round} 题）`)
      await page.goto(input.url, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(e => {
        log.warn(`打开验证页失败: ${String(e).slice(0, 120)}`)
      })
      if (input.done()) return null
      if (round === 1) {
        // 环境必须和声明的真机一致，否则 verify 直接 5014；这一行是判定依据
        const env = await page.evaluate(() => {
          const g = globalThis as unknown as {
            navigator: { platform: string; maxTouchPoints: number; hardwareConcurrency: number }
            devicePixelRatio: number
          }
          return `${g.navigator.platform} touch=${g.navigator.maxTouchPoints} cores=${g.navigator.hardwareConcurrency} dpr=${g.devicePixelRatio}`
        }).catch(() => '-')
        log.info(`页面环境 ${env}`)
      }
      step = await attempt(ctx, cdp, page, input, state)
      if (process.env.DY_PAYLOAD === '1') await dumpPayload(page)
      if (step === 'ok' || step === 'cool' || input.done()) break
      if (round < ROUNDS) log.info(`第 ${round} 题未通过，同一决策重新取题`)
    }
    if (step !== 'ok') log.warn(`本次自动过滑块未通过（${step}），交回上层`)
    return step
  } finally {
    await ctx.close().catch(() => undefined)
    await browser.close().catch(() => undefined)
    log.info('自动过滑块已退出')
  }
}
