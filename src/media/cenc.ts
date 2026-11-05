import { err } from '../error.js'
import { decryptCencSample } from './image.js'
import { entryChildStart, find, fourcc, parseBoxes, type Box } from './box.js'
import { planTrack, type TrackPlan } from './plan.js'

/* ---------------------------------------------------------------------------
 * CENC(cenc 方案) 加密 mp4 解密：私信视频 mainUrl 下载后为 encv/enca+tenc 容器，
 * 用消息 video.skey(16B AES-128) 逐样本 AES-CTR 子样本解密并去保护重组，
 * 输出可直接播放的 mp4。容器逆推自抖音实测样本（moov 在尾、senc 携带辅助数据）。
 * ------------------------------------------------------------------------- */

interface Ctx {
  buf: Buffer
  deleted: Set<Box>
  renamed: Map<Box, string>
  sizes: Map<Box, number>
}

/** 收集 moov 下所有加密轨的解密计划（只有 encv/enca sample entry 才需要处理） */
function trackPlans (buf: Buffer, moov: Box): TrackPlan[] {
  const plans: TrackPlan[] = []
  for (const trak of moov.children!.filter(node => node.type === 'trak')) {
    const minf = find(find(trak.children!, 'mdia')?.children ?? [], 'minf')
    const stbl = find(minf?.children ?? [], 'stbl')
    const stsd = stbl && find(stbl.children!, 'stsd')
    const entry = stsd?.children?.[0]
    if (!stbl || !entry || (entry.type !== 'encv' && entry.type !== 'enca')) continue
    plans.push(planTrack(buf, stbl, entry))
  }
  return plans
}

/** 逐加密轨原位解密 mdat 样本 */
function decryptSamples (buf: Buffer, plans: TrackPlan[], key: Buffer): void {
  for (const plan of plans) {
    plan.samples.forEach((sample, i) => {
      const { iv, subsamples } = plan.auxs[i]!
      const plain = decryptCencSample(buf.subarray(sample.offset, sample.offset + sample.size), key, iv, subsamples)
      plain.copy(buf, sample.offset)
    })
  }
}

/** 容器子 box 起点：stsd 固定 8 字节扩展，改名后的 sample entry 需滑窗定位 */
function prefixOf (node: Box, ctx: Ctx): number {
  if (node.type === 'stsd') return node.body + 8
  return ctx.renamed.has(node) ? entryChildStart(ctx.buf, node.body, node.end) : node.body
}

function size (node: Box, ctx: Ctx): number {
  if (ctx.deleted.has(node)) return 0
  if (!node.children) {
    const total = node.end - node.start
    ctx.sizes.set(node, total)
    return total
  }
  let total = prefixOf(node, ctx) - node.start
  for (const child of node.children) total += size(child, ctx)
  ctx.sizes.set(node, total)
  return total
}

/** moov 在 mdat 之前时删除保护 box 会使 mdat 绝对偏移前移，需修正 stco/co64 */
function shift (ctx: Ctx, moov: Box, mdat: Box, plans: TrackPlan[]): void {
  const shrink = moov.end - moov.start - (ctx.sizes.get(moov) ?? 0)
  if (moov.end > mdat.start || shrink <= 0) return
  for (const plan of plans) {
    const stco = find(plan.stbl.children!, 'stco') ?? find(plan.stbl.children!, 'co64')
    if (!stco) continue
    const n = ctx.buf.readUInt32BE(stco.body + 4)
    for (let i = 0; i < n; i++) {
      if (stco.type === 'co64') {
        const at = stco.body + 8 + i * 8
        ctx.buf.writeBigUInt64BE(ctx.buf.readBigUInt64BE(at) + BigInt(shrink), at)
      } else {
        const at = stco.body + 8 + i * 4
        ctx.buf.writeUInt32BE(ctx.buf.readUInt32BE(at) + shrink, at)
      }
    }
  }
}

function emit (node: Box, ctx: Ctx, out: Buffer, pos: number): number {
  if (ctx.deleted.has(node)) return pos
  out.writeUInt32BE(ctx.sizes.get(node)!, pos)
  out.write(ctx.renamed.get(node) ?? node.type, pos + 4, 'latin1')
  pos += 8
  if (!node.children) {
    ctx.buf.copy(out, pos, node.body, node.end)
    return pos + node.end - node.body
  }
  const prefixEnd = prefixOf(node, ctx)
  ctx.buf.copy(out, pos, node.body, prefixEnd)
  pos += prefixEnd - node.body
  for (const child of node.children) pos = emit(child, ctx, out, pos)
  return pos
}

/** 重建输出：sample entry 改回原始 fourcc，删除保护结构（sinf/senc/saiz/saio/sgpd/sbgp 的 seig 项） */
function rebuild (buf: Buffer, top: Box[], plans: TrackPlan[], moov: Box, mdat: Box): Buffer {
  const ctx: Ctx = { buf, deleted: new Set(), renamed: new Map(), sizes: new Map() }
  for (const plan of plans) {
    ctx.renamed.set(plan.entry, plan.rawFourcc)
    const sinf = find(plan.entry.children ?? [], 'sinf')
    if (sinf) ctx.deleted.add(sinf)
    for (const node of plan.stbl.children!) {
      if (node.type === 'senc' || node.type === 'saiz' || node.type === 'saio') ctx.deleted.add(node)
      if ((node.type === 'sgpd' || node.type === 'sbgp') && fourcc(buf, node.body + 4) === 'seig') ctx.deleted.add(node)
    }
  }
  for (const node of top) size(node, ctx)
  shift(ctx, moov, mdat, plans)
  const out = Buffer.alloc(top.reduce((sum, node) => sum + (ctx.sizes.get(node) ?? 0), 0))
  let pos = 0
  for (const node of top) pos = emit(node, ctx, out, pos)
  return out
}

/**
 * 解密 CENC(cenc 方案) 加密 mp4：keyHex 为消息 `video.skey`（32 hex = 16 字节 AES-128）。
 * 输出可直接播放的 mp4；未加密的输入原样返回。
 */
export function decryptCencMp4 (data: Uint8Array, keyHex: string): Buffer {
  const key = Buffer.from(keyHex, 'hex')
  if (key.length !== 16) err({ length: keyHex.length })
  const buf = Buffer.from(data)
  const top = parseBoxes(buf, 0, buf.length)
  const moov = find(top, 'moov')
  const mdat = find(top, 'mdat')
  if (!moov) err({ bytes: buf.length })
  if (!mdat) err({ bytes: buf.length })
  const plans = trackPlans(buf, moov)
  if (plans.length === 0) return buf
  decryptSamples(buf, plans, key)
  return rebuild(buf, top, plans, moov, mdat)
}
