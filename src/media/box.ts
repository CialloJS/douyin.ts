/** mp4 box 树解析：CENC 解密与去保护重建共用的容器结构 */

/** mp4 box 树节点（容器含子节点；stsd 的 sample entry 子 box 需扫描定位） */
export interface Box {
  type: string
  start: number
  body: number
  end: number
  children?: Box[]
}

/** 纯容器 box（body 全部为子 box） */
const CONTAINERS = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl', 'sinf', 'schi'])

export function fourcc (buf: Buffer, off: number): string {
  return buf.toString('latin1', off, off + 4)
}

export function find (boxes: Box[], type: string): Box | undefined {
  return boxes.find(node => node.type === type)
}

/** sample entry 固定字段（encv=78/enca=28 等）之后的子 box 起点：滑窗找首个合法 box */
export function entryChildStart (buf: Buffer, body: number, end: number): number {
  for (let off = body + 8; off + 8 <= end; off++) {
    const size = buf.readUInt32BE(off)
    if (size < 8 || off + size > end) continue
    if (/^[\x20-\x7e]{4}$/.test(fourcc(buf, off + 4))) return off
  }
  return end
}

export function parseBoxes (buf: Buffer, start: number, end: number, stsd = false): Box[] {
  const list: Box[] = []
  let off = start
  while (off + 8 <= end) {
    let size = buf.readUInt32BE(off)
    let hdr = 8
    // largesize box：size=1 时真实长度在 8 字节扩展字段（抖音的 encv/enca sample entry 即此形态）
    if (size === 1) {
      if (off + 16 > end) break
      size = Number(buf.readBigUInt64BE(off + 8))
      hdr = 16
    } else if (size === 0) {
      size = end - off
    }
    if (size < hdr || off + size > end) break
    const type = fourcc(buf, off + 4)
    const body = off + hdr
    const node: Box = { type, start: off, body, end: off + size }
    if (type === 'stsd') {
      node.children = parseBoxes(buf, body + 8, node.end, true)
    } else if (stsd || type === 'encv' || type === 'enca') {
      node.children = parseBoxes(buf, entryChildStart(buf, body, node.end), node.end)
    } else if (CONTAINERS.has(type)) {
      node.children = parseBoxes(buf, body, node.end)
    }
    list.push(node)
    off += size
  }
  return list
}
