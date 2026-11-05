import { err } from '../error.js'
import { find, fourcc, type Box } from './box.js'
import type { CencSubsample } from '../types.js'

/** 每样本解密辅助信息 */
export interface SampleAux {
  iv: Buffer
  subsamples: CencSubsample[]
}

export interface TrackPlan {
  stbl: Box
  entry: Box
  rawFourcc: string
  samples: { offset: number; size: number }[]
  auxs: SampleAux[]
}

/** 解析 tenc：KID 固定占 box 尾 16 字节（抖音将其设为解密 key），IV_size 在其前 1 字节 */
function parseTenc (tenc: Box, buf: Buffer): { ivSize: number } {
  const len = tenc.end - tenc.body
  return { ivSize: buf[tenc.body + len - 17]! }
}

/** senc box → 每样本 IV/子样本序列（抖音样本的辅助数据源；saiz/saio 为同内容的偏移定位变体，仅 senc 缺失时兜底） */
function parseAux (buf: Buffer, senc: Box | undefined, saiz: Box | undefined, saio: Box | undefined, count: number, ivSize: number): SampleAux[] {
  const auxs: SampleAux[] = []
  if (senc) {
    // 抖音视频轨 flags=2 也携带子样本，仅音频纯 IV 流 flags=0
    const withSub = (buf.readUInt32BE(senc.body) & 0xffffff) !== 0
    let off = senc.body + 8
    for (let i = 0; i < count; i++) {
      const iv = Buffer.from(buf.subarray(off, off + ivSize))
      off += ivSize
      const subsamples: CencSubsample[] = []
      if (withSub) {
        const n = buf.readUInt16BE(off)
        off += 2
        for (let k = 0; k < n; k++) {
          subsamples.push({ clear: buf.readUInt16BE(off), protected: buf.readUInt32BE(off + 2) })
          off += 6
        }
      }
      auxs.push({ iv, subsamples })
    }
    return auxs
  }
  if (saiz && saio && ivSize > 0) {
    const flags = buf[saiz.body + 7]!
    const def = buf[saiz.body + 12]!
    const sizeOf = (k: number): number => (flags & 1 ? buf[saiz.body + 17 + k]! : def)
    let aux = saio.body + 4
    if ((buf.readUInt32BE(saio.body) & 0xffffff & 1) === 1) aux += 8
    const auxBase = buf[saio.body] === 1 ? Number(buf.readBigUInt64BE(aux + 4)) : buf.readUInt32BE(aux + 4)
    let at = auxBase
    for (let i = 0; i < count; i++) {
      const iv = Buffer.from(buf.subarray(at, at + ivSize))
      const subsamples: CencSubsample[] = []
      let pos = at + ivSize
      if (sizeOf(i) > ivSize) {
        const n = buf.readUInt16BE(pos)
        pos += 2
        for (let k = 0; k < n; k++) {
          subsamples.push({ clear: buf.readUInt16BE(pos), protected: buf.readUInt32BE(pos + 2) })
          pos += 6
        }
      }
      at += sizeOf(i)
      auxs.push({ iv, subsamples })
    }
    return auxs
  }
  return auxs
}

/** 从 stbl 组装解密计划：样本定位（stsz/stsc/stco）+ 每样本 IV/子样本（senc 或 saiz/saio 或 constant_iv） */
export function planTrack (buf: Buffer, stbl: Box, entry: Box): TrackPlan {
  const sinf = find(entry.children ?? [], 'sinf')
  const frma = find(sinf?.children ?? [], 'frma')
  const tenc = find(find(sinf?.children ?? [], 'schi')?.children ?? [], 'tenc')
  if (!sinf || !frma || !tenc) err({ bytes: buf.length })
  const { ivSize } = parseTenc(tenc, buf)
  if (ivSize !== 8 && ivSize !== 16) err({ ivSize })

  const stsz = find(stbl.children!, 'stsz')
  const stsc = find(stbl.children!, 'stsc')
  const stco = find(stbl.children!, 'stco') ?? find(stbl.children!, 'co64')
  if (!stsz || !stco || !stsc) err({ bytes: buf.length })

  const b = stsz.body
  const uniform = buf.readUInt32BE(b + 4)
  const count = buf.readUInt32BE(b + 8)
  const sizes: number[] = []
  for (let i = 0; i < count; i++) sizes.push(uniform > 0 ? uniform : buf.readUInt32BE(b + 12 + i * 4))

  // stsc → 每 chunk 样本数序列；stco → chunk 绝对偏移；展开全部样本位置
  const chunkCounts: number[] = []
  {
    const n = buf.readUInt32BE(stsc.body + 4)
    const chunks = buf.readUInt32BE(stco.body + 4)
    for (let i = 0; i < n; i++) {
      const base = stsc.body + 8 + i * 12
      const first = buf.readUInt32BE(base)
      const per = buf.readUInt32BE(base + 4)
      const span = (i + 1 < n ? buf.readUInt32BE(stsc.body + 8 + (i + 1) * 12) : chunks + 1) - first
      for (let j = 0; j < span; j++) chunkCounts.push(per)
    }
  }
  const samples: { offset: number; size: number }[] = []
  {
    let index = 0
    for (let c = 0; c < chunkCounts.length && index < count; c++) {
      const base = stco.type === 'co64' ? stco.body + 8 + c * 8 : stco.body + 8 + c * 4
      const offset = stco.type === 'co64' ? Number(buf.readBigUInt64BE(base)) : buf.readUInt32BE(base)
      let acc = 0
      for (let j = 0; j < chunkCounts[c]! && index < count; j++) {
        samples.push({ offset: offset + acc, size: sizes[index]! })
        acc += sizes[index]!
        index++
      }
    }
  }

  const auxs = parseAux(buf, find(stbl.children!, 'senc'), find(stbl.children!, 'saiz'), find(stbl.children!, 'saio'), count, ivSize)
  if (auxs.length !== count) err({ aux: auxs.length, count })
  return { stbl, entry, rawFourcc: fourcc(buf, frma.body), samples, auxs }
}
