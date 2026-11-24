/**
 * AArch64 解释器使用的线性内存。
 *
 * 地址用 number（被测 so 的映射全部落在 0x4000_0000 ~ 0xfffd_ffff，远小于 2^53），
 * 按 64 KiB 分页存放，未映射页访问直接抛错——这是发现「加载不全」最有效的手段。
 */

const PAGE_BITS = 16;
const PAGE_SIZE = 1 << PAGE_BITS;
const PAGE_OFF = PAGE_SIZE - 1;

export interface ArmMem {
  /** 取指：读 4 字节小端（热路径，单独优化） */
  fetch(addr: number): number;
  /** 读 size ∈ {1,2,4,8} 字节小端 */
  read(addr: number, size: number): bigint;
  /** 写 size ∈ {1,2,4,8} 字节小端 */
  write(addr: number, size: number, v: bigint): void;
  /** 快路径：无 BigInt 的定长读写 */
  ld8(addr: number): number;
  ld16(addr: number): number;
  ld32(addr: number): number;
  /** 读 8 字节：返回低 32 位，高 32 位写入 out[0] */
  ld64(addr: number, out: Int32Array): number;
  st8(addr: number, v: number): void;
  st16(addr: number, v: number): void;
  st32(addr: number, v: number): void;
  st64(addr: number, lo: number, hi: number): void;
  /** 调试：写日志（4 元组 addr,size,lo,hi），对拍用 */
  wlog: number[] | null;
}

export class PageMem implements ArmMem {
  /** 页表：下标 = addr >>> 16（稀疏数组，未分配为 undefined；JIT 直接读它） */
  readonly pt: (Uint8Array | undefined)[] = [];
  /** 与 pt 平行的 DataView 视图（JIT 用：多字节访存比逐字节拼装快一倍） */
  readonly dv: (DataView | undefined)[] = [];
  /** 已映射区间 [lo, hi)，页在首次访问时按需分配（避免一次性分配上百 MB） */
  private readonly rlo: number[] = [];
  private readonly rhi: number[] = [];
  /** 最近访问的页缓存（取指/读写绝大多数命中同一页） */
  private lastIdx = -1;
  private lastPage: Uint8Array | null = null;
  /** 调试用写监视（只在设置时生效） */
  watch: { lo: number; hi: number; cb: (addr: number, size: number, v: bigint) => void } | null = null;
  /** 调试用写监视 2（与 watch 并行，互不覆盖） */
  watch2: { lo: number; hi: number; cb: (addr: number, size: number, v: bigint) => void } | null = null;
  /** 调试用写监视 3（仅作门控触发用） */
  watch3: { lo: number; hi: number; cb: (addr: number, size: number, v: bigint) => void } | null = null;
  /** 调试用读监视（只在设置时生效） */
  watchRead: { cb: (addr: number, size: number, v: bigint) => void } | null = null;
  /** 调试：写日志（4 元组 addr,size,lo,hi），对拍用 */
  wlog: number[] | null = null;

  /** 分配 [base, base+size)（已存在则保留原内容；页按需分配） */
  map(base: number, size: number): void {
    // 用算术而不是位运算：位运算在 0x8000_0000 以上会变负数
    const b = base >>> 0;
    const lo = b - (b % PAGE_SIZE);
    const end = b + Math.max(0, size);
    const hi = Math.ceil(end / PAGE_SIZE) * PAGE_SIZE;
    for (let i = 0; i < this.rlo.length; i++) if (lo >= this.rlo[i] && hi <= this.rhi[i]) return;
    this.rlo.push(lo);
    this.rhi.push(hi);
  }

  private inRange(addr: number): boolean {
    const rlo = this.rlo;
    const rhi = this.rhi;
    for (let i = 0; i < rlo.length; i++) if (addr >= rlo[i] && addr < rhi[i]) return true;
    return false;
  }

  /** 把 data 写入 base 起（自动分配页，按页批量拷贝） */
  load(base: number, data: Uint8Array): void {
    this.map(base, data.length);
    let off = 0;
    while (off < data.length) {
      const a = base + off;
      const page = this.page(a);
      const pageOff = a & PAGE_OFF;
      const n = Math.min(PAGE_SIZE - pageOff, data.length - off);
      page.set(data.subarray(off, off + n), pageOff);
      off += n;
    }
  }

  /** 拷贝一段出来（调试/对拍用） */
  slice(base: number, size: number): Uint8Array {
    const out = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      const a = base + i;
      out[i] = this.page(a)[a & PAGE_OFF];
    }
    return out;
  }

  /** 等价 memmove：把 [src, src+n) 拷到 dst（允许重叠） */
  copy(dst: number, src: number, n: number): void {
    if (n <= 0 || dst === src) return;
    if (dst < src || dst >= src + n) {
      let off = 0;
      while (off < n) {
        const s = src + off;
        const d = dst + off;
        const sp = this.page(s);
        const dp = this.page(d);
        const so = s & PAGE_OFF;
        const dofs = d & PAGE_OFF;
        const k = Math.min(PAGE_SIZE - so, PAGE_SIZE - dofs, n - off);
        dp.set(sp.subarray(so, so + k), dofs);
        off += k;
      }
      return;
    }
    const tmp = this.slice(src, n);
    this.load(dst, tmp);
  }

  /** 等价 memset */
  fill(dst: number, v: number, n: number): void {
    const b = v & 0xff;
    let off = 0;
    while (off < n) {
      const d = dst + off;
      const dp = this.page(d);
      const dofs = d & PAGE_OFF;
      const k = Math.min(PAGE_SIZE - dofs, n - off);
      dp.fill(b, dofs, dofs + k);
      off += k;
    }
  }

  /** 取页并确保已分配（未映射则抛错）；JIT 的慢路径也走它 */
  mkpage(addr: number): Uint8Array {
    const idx = addr >>> PAGE_BITS;
    let p = this.pt[idx];
    if (p === undefined) {
      if (!this.inRange(addr)) throw new Error(`访问未映射地址 0x${(addr >>> 0).toString(16)}`);
      p = new Uint8Array(PAGE_SIZE);
      this.pt[idx] = p;
      this.dv[idx] = new DataView(p.buffer);
    }
    this.lastIdx = idx;
    this.lastPage = p;
    return p;
  }

  /** 取页的 DataView（未分配则分配）；JIT 快路径用 */
  mkdv(addr: number): DataView {
    const p = this.mkpage(addr);
    const idx = addr >>> PAGE_BITS;
    let d = this.dv[idx];
    if (d === undefined) {
      d = new DataView(p.buffer);
      this.dv[idx] = d;
    }
    return d;
  }

  private page(addr: number): Uint8Array {
    const idx = addr >>> PAGE_BITS;
    if (idx === this.lastIdx) return this.lastPage!;
    return this.mkpage(addr);
  }

  /** 页被外部重建/回收后清掉「最近一页」缓存（快照恢复用） */
  invalidate(): void {
    this.lastIdx = -1;
    this.lastPage = null;
  }

  fetch(addr: number): number {
    const off = addr & PAGE_OFF;
    if (off + 4 <= PAGE_SIZE) {
      const idx = addr >>> PAGE_BITS;
      let p: Uint8Array;
      if (idx === this.lastIdx) p = this.lastPage!;
      else {
        const q = this.pt[idx];
        if (q === undefined) {
          if (!this.inRange(addr)) throw new Error(`取指未映射地址 0x${(addr >>> 0).toString(16)}`);
          p = new Uint8Array(PAGE_SIZE);
          this.pt[idx] = p;
        } else p = q;
        this.lastIdx = idx;
        this.lastPage = p;
      }
      return (p[off] | (p[off + 1] << 8) | (p[off + 2] << 16) | (p[off + 3] << 24)) >>> 0;
    }
    return Number(this.readRaw(addr, 4));
  }

  read(addr: number, size: number): bigint {
    const v = this.readRaw(addr, size);
    const w = this.watchRead;
    if (w !== null) w.cb(addr, size, v);
    return v;
  }

  private readRaw(addr: number, size: number): bigint {
    const off = addr & PAGE_OFF;
    if (off + size <= PAGE_SIZE) {
      const p = this.page(addr);
      switch (size) {
        case 1: return BigInt(p[off]);
        case 2: return BigInt(p[off] | (p[off + 1] << 8));
        case 4: return BigInt((p[off] | (p[off + 1] << 8) | (p[off + 2] << 16) | (p[off + 3] << 24)) >>> 0);
        default: {
          const lo = (p[off] | (p[off + 1] << 8) | (p[off + 2] << 16) | (p[off + 3] << 24)) >>> 0;
          const hi = (p[off + 4] | (p[off + 5] << 8) | (p[off + 6] << 16) | (p[off + 7] << 24)) >>> 0;
          return (BigInt(hi) << 32n) | BigInt(lo);
        }
      }
    }
    // 跨页：逐字节
    let v = 0n;
    for (let i = 0; i < size; i++) {
      const a = addr + i;
      v |= BigInt(this.page(a)[a & PAGE_OFF]) << BigInt(i * 8);
    }
    return v;
  }

  write(addr: number, size: number, v: bigint): void {
    const w = this.watch;
    if (w !== null && addr < w.hi && addr + size > w.lo) w.cb(addr, size, v);
    const w2 = this.watch2;
    if (w2 !== null && addr < w2.hi && addr + size > w2.lo) w2.cb(addr, size, v);
    const w3 = this.watch3;
    if (w3 !== null && addr < w3.hi && addr + size > w3.lo) w3.cb(addr, size, v);
    const lg = this.wlog;
    if (lg !== null) {
      // 必须按 32 位分段取，直接 Number(v & m) 在 |v| >= 2^53 时会丢精度
      lg.push(addr, size, Number(v & 0xffffffffn) | 0, Number((v >> 32n) & 0xffffffffn) | 0);
    }
    const off = addr & PAGE_OFF;
    if (off + size <= PAGE_SIZE) {
      const p = this.page(addr);
      switch (size) {
        case 1:
          p[off] = Number(v & 0xffn);
          return;
        case 2:
          p[off] = Number(v & 0xffn);
          p[off + 1] = Number((v >> 8n) & 0xffn);
          return;
        case 4: {
          const x = Number(v & 0xffffffffn);
          p[off] = x & 0xff;
          p[off + 1] = (x >>> 8) & 0xff;
          p[off + 2] = (x >>> 16) & 0xff;
          p[off + 3] = (x >>> 24) & 0xff;
          return;
        }
        default: {
          const lo = Number(v & 0xffffffffn);
          const hi = Number((v >> 32n) & 0xffffffffn);
          p[off] = lo & 0xff;
          p[off + 1] = (lo >>> 8) & 0xff;
          p[off + 2] = (lo >>> 16) & 0xff;
          p[off + 3] = (lo >>> 24) & 0xff;
          p[off + 4] = hi & 0xff;
          p[off + 5] = (hi >>> 8) & 0xff;
          p[off + 6] = (hi >>> 16) & 0xff;
          p[off + 7] = (hi >>> 24) & 0xff;
          return;
        }
      }
    }
    for (let i = 0; i < size; i++) {
      const a = addr + i;
      this.page(a)[a & PAGE_OFF] = Number((v >> BigInt(i * 8)) & 0xffn);
    }
  }

  /** 读 C 字符串（调试用） */
  cstr(addr: number, limit = 4096): string {
    const out: number[] = [];
    for (let i = 0; i < limit; i++) {
      const b = Number(this.read(addr + i, 1));
      if (b === 0) break;
      out.push(b);
    }
    return Buffer.from(out).toString('utf8');
  }

  // ---------------------------------------------------------------- JIT 快路径
  // 不产生 BigInt、不检查 watch（JIT 在开启任何调试开关时整体关闭）。
  ld8(addr: number): number {
    return this.page(addr)[addr & PAGE_OFF];
  }

  ld16(addr: number): number {
    const o = addr & PAGE_OFF;
    if (o + 2 > PAGE_SIZE) return Number(this.readRaw(addr, 2));
    const p = this.page(addr);
    return p[o] | (p[o + 1] << 8);
  }

  ld32(addr: number): number {
    const o = addr & PAGE_OFF;
    if (o + 4 > PAGE_SIZE) return Number(this.readRaw(addr, 4)) | 0;
    const p = this.page(addr);
    return (p[o] | (p[o + 1] << 8) | (p[o + 2] << 16) | (p[o + 3] << 24)) | 0;
  }

  /** 64 位读：返回低 32 位，高 32 位写入 out[0] */
  ld64(addr: number, out: Int32Array): number {
    const o = addr & PAGE_OFF;
    if (o + 8 > PAGE_SIZE) {
      const v = this.readRaw(addr, 8);
      out[0] = Number((v >> 32n) & 0xffffffffn);
      return Number(v & 0xffffffffn) | 0;
    }
    const p = this.page(addr);
    out[0] = (p[o + 4] | (p[o + 5] << 8) | (p[o + 6] << 16) | (p[o + 7] << 24)) | 0;
    return (p[o] | (p[o + 1] << 8) | (p[o + 2] << 16) | (p[o + 3] << 24)) | 0;
  }

  st8(addr: number, v: number): void {
    const lg = this.wlog;
    if (lg !== null) lg.push(addr, 1, v & 0xff, 0);
    this.page(addr)[addr & PAGE_OFF] = v & 0xff;
  }

  st16(addr: number, v: number): void {
    const o = addr & PAGE_OFF;
    if (o + 2 > PAGE_SIZE) {
      this.write(addr, 2, BigInt(v & 0xffff));
      return;
    }
    const lg = this.wlog;
    if (lg !== null) lg.push(addr, 2, v & 0xffff, 0);
    const p = this.page(addr);
    p[o] = v & 0xff;
    p[o + 1] = (v >>> 8) & 0xff;
  }

  st32(addr: number, v: number): void {
    const o = addr & PAGE_OFF;
    if (o + 4 > PAGE_SIZE) {
      this.write(addr, 4, BigInt(v >>> 0));
      return;
    }
    const lg = this.wlog;
    if (lg !== null) lg.push(addr, 4, v | 0, 0);
    const p = this.page(addr);
    p[o] = v & 0xff;
    p[o + 1] = (v >>> 8) & 0xff;
    p[o + 2] = (v >>> 16) & 0xff;
    p[o + 3] = (v >>> 24) & 0xff;
  }

  st64(addr: number, lo: number, hi: number): void {
    const o = addr & PAGE_OFF;
    if (o + 8 > PAGE_SIZE) {
      this.write(addr, 8, (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0));
      return;
    }
    const lg = this.wlog;
    if (lg !== null) lg.push(addr, 8, lo, hi);
    const p = this.page(addr);
    p[o] = lo & 0xff;
    p[o + 1] = (lo >>> 8) & 0xff;
    p[o + 2] = (lo >>> 16) & 0xff;
    p[o + 3] = (lo >>> 24) & 0xff;
    p[o + 4] = hi & 0xff;
    p[o + 5] = (hi >>> 8) & 0xff;
    p[o + 6] = (hi >>> 16) & 0xff;
    p[o + 7] = (hi >>> 24) & 0xff;
  }
}
