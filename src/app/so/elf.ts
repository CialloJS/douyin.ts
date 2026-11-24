/**
 * 最小 ELF64 (AArch64) 解析/加载器：只覆盖「从 .so 冷启动」需要的部分。
 *
 * 与 unidbg 的行为对齐：
 * - 按 64 KiB 粒度映射每个 PT_LOAD（unidbg 的内存快照正是 64K 对齐切分的）；
 * - 导出表取 .dynsym 里已定义的 GLOBAL/WEAK 符号（st_value != 0）；
 * - 重定位只处理 AArch64 的 ABS64 / GLOB_DAT / JUMP_SLOT / RELATIVE。
 */

import { readFileSync } from 'node:fs';

import { PageMem } from './mem.js';

const PT_LOAD = 1;
const PT_DYNAMIC = 2;

const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_PLTRELSZ = 2;
const DT_HASH = 4;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_RELA = 7;
const DT_RELASZ = 8;
const DT_SONAME = 14;
const DT_PLTREL = 20;
const DT_JMPREL = 23;
const DT_INIT_ARRAY = 25;
const DT_FINI_ARRAY = 26;
const DT_INIT_ARRAYSZ = 27;
const DT_FINI_ARRAYSZ = 28;

export const R_AARCH64_ABS64 = 257;
export const R_AARCH64_GLOB_DAT = 1025;
export const R_AARCH64_JUMP_SLOT = 1026;
export const R_AARCH64_RELATIVE = 1027;

export interface ElfSegment {
  flags: number;
  offset: number;
  vaddr: number;
  filesz: number;
  memsz: number;
}

export interface ElfReloc {
  /** 写入位置（模块内偏移） */
  offset: number;
  type: number;
  /** 符号名；RELATIVE 为空串 */
  sym: string;
  addend: number;
}

export interface ElfSymbol {
  name: string;
  value: number;
  size: number;
  bind: number;
  type: number;
  shndx: number;
}

/** 一个已解析的 ELF 镜像（未映射） */
export class ElfImage {
  readonly data: Uint8Array;
  readonly segments: ElfSegment[] = [];
  readonly exports = new Map<string, number>();
  readonly symbols: ElfSymbol[] = [];
  readonly relocs: ElfReloc[] = [];
  /** .init_array / .fini_array 的虚拟地址与字节数（内容要等重定位后从内存读） */
  initArrayVa = 0;
  initArraySize = 0;
  finiArrayVa = 0;
  finiArraySize = 0;
  soname = '';
  needed: string[] = [];
  /** 最后一个 PT_LOAD 的 vaddr+memsz，再按 64 KiB 上取整 */
  extent = 0;

  constructor(readonly path: string) {
    this.data = new Uint8Array(readFileSync(path));
    this.parse();
  }

  private u16(o: number): number {
    return this.data[o] | (this.data[o + 1] << 8);
  }

  private u32(o: number): number {
    const d = this.data;
    return (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0;
  }

  private u64(o: number): number {
    return Number(new DataView(this.data.buffer, this.data.byteOffset).getBigUint64(o, true));
  }

  private i64(o: number): number {
    return Number(new DataView(this.data.buffer, this.data.byteOffset).getBigInt64(o, true));
  }

  /** 虚拟地址 → 文件偏移（PT_LOAD 覆盖范围内） */
  vaToOff(va: number): number {
    for (const s of this.segments) {
      if (va >= s.vaddr && va < s.vaddr + s.filesz) return s.offset + (va - s.vaddr);
    }
    throw new Error(`${this.path}: va 0x${va.toString(16)} 不在任何 PT_LOAD 内`);
  }

  private cstr(off: number): string {
    let e = off;
    while (this.data[e] !== 0) e += 1;
    return Buffer.from(this.data.subarray(off, e)).toString('utf8');
  }

  private parse(): void {
    const d = this.data;
    if (this.u32(0) !== 0x464c457f) throw new Error(`${this.path}: 不是 ELF`);
    if (d[4] !== 2 || d[5] !== 1) throw new Error(`${this.path}: 只支持 ELF64 小端`);

    const phoff = this.u64(32);
    const phentsize = this.u16(54);
    const phnum = this.u16(56);
    let dynOff = 0;
    let dynSize = 0;
    for (let i = 0; i < phnum; i++) {
      const o = phoff + i * phentsize;
      const type = this.u32(o);
      if (type === PT_LOAD) {
        this.segments.push({
          flags: this.u32(o + 4),
          offset: this.u64(o + 8),
          vaddr: this.u64(o + 16),
          filesz: this.u64(o + 32),
          memsz: this.u64(o + 40),
        });
      } else if (type === PT_DYNAMIC) {
        dynOff = this.u64(o + 8);
        dynSize = this.u64(o + 32);
      }
    }
    if (this.segments.length === 0) throw new Error(`${this.path}: 没有 PT_LOAD`);

    const tags = new Map<number, number>();
    for (let o = dynOff; o < dynOff + dynSize; o += 16) {
      const tag = this.i64(o);
      if (tag === DT_NULL) break;
      if (!tags.has(tag)) tags.set(tag, this.u64(o + 8));
    }
    const strtabVa = tags.get(DT_STRTAB);
    const symtabVa = tags.get(DT_SYMTAB);
    if (strtabVa === undefined || symtabVa === undefined) {
      throw new Error(`${this.path}: 缺少 DT_STRTAB/DT_SYMTAB`);
    }
    const strtab = this.vaToOff(strtabVa);
    const symtab = this.vaToOff(symtabVa);
    const symName = (off: number): string => this.cstr(strtab + off);

    const so = tags.get(DT_SONAME);
    if (so !== undefined) this.soname = symName(so);
    for (const [tag, val] of tags) if (tag === DT_NEEDED) this.needed.push(symName(val));

    // 符号数量：优先 DT_HASH 的 nchain，其次按 .dynstr 起点反推
    let nsym = 0;
    const hashVa = tags.get(DT_HASH);
    if (hashVa !== undefined) nsym = this.u32(this.vaToOff(hashVa) + 4);
    if (nsym === 0) nsym = Math.floor((strtab - symtab) / 24);
    if (nsym <= 0) throw new Error(`${this.path}: 无法确定 dynsym 数量`);

    for (let i = 0; i < nsym; i++) {
      const o = symtab + i * 24;
      const name = symName(this.u32(o));
      const info = d[o + 4];
      const shndx = this.u16(o + 6);
      const value = this.u64(o + 8);
      const size = this.u64(o + 16);
      const sym: ElfSymbol = { name, value, size, bind: info >> 4, type: info & 0xf, shndx };
      this.symbols.push(sym);
      if (shndx !== 0 && value !== 0 && (sym.bind === 1 || sym.bind === 2) && name !== '') {
        if (!this.exports.has(name)) this.exports.set(name, value);
      }
    }

    // 重定位
    const relaVa = tags.get(DT_RELA);
    const relaSz = tags.get(DT_RELASZ) ?? 0;
    const jmpVa = tags.get(DT_JMPREL);
    const jmpSz = tags.get(DT_PLTRELSZ) ?? 0;
    if (tags.get(DT_PLTREL) !== undefined && tags.get(DT_PLTREL) !== 7) {
      throw new Error(`${this.path}: 只支持 RELA 形式的 PLT 重定位`);
    }
    const scan = (va: number, size: number): void => {
      if (va === undefined || size === 0) return;
      const base = this.vaToOff(va);
      for (let o = base; o < base + size; o += 24) {
        const offset = this.u64(o);
        const info = BigInt(this.u64(o + 8));
        const type = Number(info & 0xffffffffn);
        const symIdx = Number(info >> 32n);
        const sym = symIdx !== 0 ? this.symbols[symIdx]?.name ?? '' : '';
        this.relocs.push({ offset, type, sym, addend: this.i64(o + 16) });
      }
    };
    scan(relaVa ?? 0, relaSz);
    scan(jmpVa ?? 0, jmpSz);

    this.initArrayVa = tags.get(DT_INIT_ARRAY) ?? 0;
    this.initArraySize = tags.get(DT_INIT_ARRAYSZ) ?? 0;
    this.finiArrayVa = tags.get(DT_FINI_ARRAY) ?? 0;
    this.finiArraySize = tags.get(DT_FINI_ARRAYSZ) ?? 0;

    let end = 0;
    for (const s of this.segments) end = Math.max(end, s.vaddr + s.memsz);
    this.extent = (end + 0xffff) & ~0xffff;
  }
}

/** 把镜像按 64 KiB 粒度映射到 base 并写入文件内容（bss 保持 0） */
export function mapImage(mem: PageMem, img: ElfImage, base: number): void {
  for (const s of img.segments) {
    const lo = base + s.vaddr;
    const hi = base + s.vaddr + s.memsz;
    mem.map(lo & ~0xffff, ((hi + 0xffff) & ~0xffff) - (lo & ~0xffff));
    if (s.filesz > 0) {
      mem.load(lo, img.data.subarray(s.offset, s.offset + s.filesz));
    }
  }
}

/** 读 .init_array（必须在 applyRelocs 之后），返回绝对地址列表 */
export function readInitArray(mem: PageMem, img: ElfImage, base: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < img.initArraySize; i += 8) {
    out.push(Number(mem.read(base + img.initArrayVa + i, 8)));
  }
  return out;
}

export interface RelocStats {
  applied: number;
  /** 找不到的导入符号（name → 出现次数） */
  unresolved: Map<string, number>;
}

/**
 * 应用重定位（mapImage 之后调用）。resolve(name) 返回符号绝对地址，找不到返回 0。
 * 未解析的 GLOB_DAT/JUMP_SLOT 记入 unresolved（槽位写 0）。
 */
export function applyRelocs(
  mem: PageMem,
  img: ElfImage,
  base: number,
  resolve: (name: string) => number,
): RelocStats {
  const stats: RelocStats = { applied: 0, unresolved: new Map() };
  for (const r of img.relocs) {
    const at = base + r.offset;
    switch (r.type) {
      case R_AARCH64_RELATIVE:
        mem.write(at, 8, BigInt(base + r.addend));
        stats.applied += 1;
        break;
      case R_AARCH64_ABS64:
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT: {
        const addr = resolve(r.sym);
        if (addr === 0) {
          stats.unresolved.set(r.sym, (stats.unresolved.get(r.sym) ?? 0) + 1);
          mem.write(at, 8, 0n);
        } else {
          mem.write(at, 8, BigInt(r.type === R_AARCH64_ABS64 ? addr + r.addend : addr));
          stats.applied += 1;
        }
        break;
      }
      default:
        throw new Error(`${img.path}: 未支持的重定位类型 ${r.type} (sym=${r.sym})`);
    }
  }
  return stats;
}
