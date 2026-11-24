/**
 * 块级 JIT：把一个基本块（顺序执行到控制流指令为止）翻译成一个 JS 函数。
 *
 * 生成的函数直接读写 cpu.xlo/xhi/vi，省掉逐条 fetch/classify/dispatch 的开销；
 * 语义与 cpu.execFast 一一对应（同一份位域解码、同一套 lo/hi 运算顺序）。
 */
import {
  classify, Cpu, C_ADR, C_ADDSUB_EXT, C_ADDSUB_IMM, C_ADDSUB_SHIFT, C_BARRIER, C_BBL,
  C_BCOND, C_BITFIELD, C_BLR, C_BR, C_BRK, C_BTI, C_CBZ, C_CLREX, C_CSEL, C_DP2, C_EXTR,
  C_FMOV_WS, C_HINT, C_LDST_LIT, C_LDST_POST, C_LDST_PRE, C_LDST_ROFF, C_LDST_UNSCALED,
  C_LDST_UOFF, C_LOGIC_IMM, C_LOGIC_SHIFT, C_MOVEWIDE, C_PAC, C_PAIR, C_RET, C_SVC, C_TBZ,
  C_VEC_DUP_EL, C_VEC_DUP_GEN, C_VEC_EXT, C_VEC_LOGIC, C_VEC_UMOV, C_VEC_USHL, C_VEC_UZP1,
  C_VEC_ZIP1, C_XPACLRI,
} from './cpu.js';
import type { PageMem } from './mem.js';

export interface JitBlock {
  f: (cpu: Cpu) => void;
  /** 块内指令条数（预算统计用） */
  n: number;
  /** SO_JITSTAT：执行次数与生成源码（调优用） */
  c?: number;
  src?: string;
}

/** 单块最大指令数（太大不利于 V8 优化） */
const MAX_BLOCK = 80;

export class Jit {
  /** pc 快查表：值 = list 下标 + 1，0 表示未编译 */
  readonly idx: Int32Array;
  /** idx 指向的块 */
  readonly list: JitBlock[] = [];
  /** 快查表覆盖的代码区间 [codeLo, codeHi) */
  readonly codeLo: number;
  readonly codeHi: number;
  /** 每个 64KiB 页是否有 hook（1 = 有） */
  readonly hookPages: Uint8Array;
  /** 代码区间外的块（正常不会用到） */
  readonly slowBlocks = new Map<number, JitBlock>();
  private L: string[] = [];
  private u = 0;

  constructor(
    private readonly cpu: Cpu,
    private readonly mem: PageMem,
    private readonly stopPc: number,
    private readonly hooks: Map<number, (c: Cpu) => boolean>,
    /** 调试用：这些指令类不走内联，直接回退解释器（二分定位语义差异） */
    private readonly skip?: Set<number>,
    codeLo = 0,
    codeHi = 0,
  ) {
    const span = codeHi > codeLo ? codeHi - codeLo : 0;
    this.codeLo = codeLo;
    this.codeHi = codeLo + span;
    this.idx = new Int32Array(span >>> 2);
    this.hookPages = new Uint8Array((span >>> 16) + 1);
    for (const p of hooks.keys()) {
      const off = p - codeLo;
      if (off >= 0 && off < span) this.hookPages[off >>> 16] = 1;
    }
  }

  /** 编译从 startPc 开始的基本块（块尾一定是「设好 cpu.pc 后 return」） */
  compile(startPc: number): JitBlock {
    this.L = [];
    this.u = 0;
    this.e('let rlo=0,rhi=0;');
    let addr = startPc;
    let n = 0;
    /** -1 = 需要补块尾；-2 = 已由指令自己设好 pc 并 return */
    let tail = -1;
    for (;;) {
      // 块首允许落在 hook pc 上（驱动会先调 hook，返回 false 时才执行该条）
      if (addr === this.stopPc || (n > 0 && this.hooks.has(addr))) break;
      const w = this.mem.fetch(addr);
      const cont = this.emitInstr(addr, w, classify(w));
      n += 1;
      addr += 4;
      if (!cont) {
        tail = -2;
        break;
      }
      if (n >= MAX_BLOCK) break;
    }
    // tail === -1：块尾统一设 pc（含 n === 0 的空块，保持 pc 不变）
    if (tail === -1) this.e(`cpu.pc=${addr};`);
    const body = this.L.join('');
    // 按需绑定：短块（均值约 10 条）省掉用不到的属性读取
    let head = 'const XLO=cpu.xlo,XHI=cpu.xhi';
    if (body.includes('VI[')) head += ',VI=cpu.vi';
    if (body.includes('DV[')) head += ',MEM=cpu.mem,DV=MEM.dv';
    else if (body.includes('MEM.')) head += ',MEM=cpu.mem';
    if (body.includes('T1[')) head += ',T1=cpu.t1';
    const src = `${head};${body}`;
    const f = new Function('cpu', src) as (c: Cpu) => void;
    const b: JitBlock = { f, n };
    if (Jit.STAT) {
      b.c = 0;
      b.src = src;
    }
    const k = startPc - this.codeLo;
    if (k >= 0 && k < this.codeHi - this.codeLo) {
      this.idx[k >>> 2] = this.list.length + 1;
      this.list.push(b);
    } else {
      this.slowBlocks.set(startPc, b);
    }
    return b;
  }

  // ------------------------------------------------------------ 发射原语

  private e(s: string): void {
    this.L.push(s);
  }

  /** 读寄存器（x31 = xzr） */
  private rl(r: number): string {
    return r === 31 ? '0' : `XLO[${r}]`;
  }

  private rh(r: number): string {
    return r === 31 ? '0' : `XHI[${r}]`;
  }

  /** 写 64 位（x31 = xzr 丢弃） */
  private wr64(rd: number, lo: string, hi: string): void {
    if (rd === 31) return;
    this.e(`XLO[${rd}]=(${lo})|0;XHI[${rd}]=(${hi})|0;`);
  }

  /** 写 32 位（高位清零） */
  private wr32(rd: number, v: string): void {
    if (rd === 31) return;
    this.e(`XLO[${rd}]=(${v})|0;XHI[${rd}]=0;`);
  }

  /**
   * ADD/SUB 类写回：不置标志位时 rd=31 是 SP（必须写）；
   * 置标志位时（CMP/CMN 等）rd=31 是 XZR（丢弃）。
   */
  private wrAddsub(rd: number, sf: number, setF: boolean): void {
    if (setF) {
      if (sf === 0) this.wr32(rd, 'rlo');
      else this.wr64(rd, 'rlo', 'rhi');
      return;
    }
    if (sf === 0) this.e(`XLO[${rd}]=rlo|0;XHI[${rd}]=0;`);
    else this.e(`XLO[${rd}]=rlo|0;XHI[${rd}]=rhi|0;`);
  }

  /** 对 rlo/rhi 做 LSL/LSR/ASR/ROR（type 0/1/2/3），amount 为立即数 */
  private emitShift(sf: number, type: number, amount: number): void {
    const n = sf === 1 ? amount & 63 : amount & 31;
    if (sf === 1) {
      if (n === 0) return;
      if (type === 0) {
        if (n < 32) this.e(`rhi=(rhi<<${n})|(rlo>>>(32-${n}));rlo=rlo<<${n};`);
        else if (n === 32) this.e('rhi=rlo;rlo=0;');
        else this.e(`rhi=rlo<<${n - 32};rlo=0;`);
      } else if (type === 1) {
        if (n < 32) this.e(`rlo=(rlo>>>${n})|(rhi<<${32 - n});rhi=rhi>>>${n};`);
        else if (n === 32) this.e('rlo=rhi;rhi=0;');
        else this.e(`rlo=rhi>>>${n - 32};rhi=0;`);
      } else if (type === 2) {
        if (n < 32) this.e(`rlo=(rlo>>>${n})|(rhi<<${32 - n});rhi=rhi>>${n};`);
        else if (n === 32) this.e('rlo=rhi;rhi=rhi>>31;');
        else this.e(`rlo=rhi>>${n - 32};rhi=rhi>>31;`);
      } else if (n < 32) {
        const q = `q${this.u++}`;
        this.e(`let ${q}=rlo;rlo=(rlo>>>${n})|(rhi<<${32 - n});` +
          `rhi=(rhi>>>${n})|(${q}<<${32 - n});`);
      } else if (n === 32) {
        const q = `q${this.u++}`;
        this.e(`let ${q}=rlo;rlo=rhi;rhi=${q};`);
      } else {
        const q = `q${this.u++}`;
        const m = n - 32;
        this.e(`let ${q}=rlo;rlo=(rhi>>>${m})|(rlo<<${32 - m});` +
          `rhi=(${q}>>>${m})|(rhi<<${32 - m});`);
      }
      return;
    }
    if (type === 0) this.e(`rlo=rlo<<${n};rhi=0;`);
    else if (type === 1) this.e(`rlo=rlo>>>${n};rhi=0;`);
    else if (type === 2) this.e(`rlo=rlo>>${n};rhi=0;`);
    else if (n === 0) this.e('rhi=0;');
    else this.e(`rlo=(rlo>>>${n})|(rlo<<${32 - n});rhi=0;`);
  }

  /** 对 rlo/rhi 做 UXTB..SXTX（opt 0..7）再 LSL #shift */
  private emitExtend(opt: number, shift: number, sf: number): void {
    if (opt === 0) this.e('rlo=rlo&255;rhi=0;');
    else if (opt === 1) this.e('rlo=rlo&65535;rhi=0;');
    else if (opt === 2) this.e('rhi=0;');
    else if (opt === 4) this.e('rlo=(rlo<<24)>>24;rhi=rlo>>31;');
    else if (opt === 5) this.e('rlo=(rlo<<16)>>16;rhi=rlo>>31;');
    else if (opt === 6) this.e('rhi=rlo>>31;');
    const n = sf === 1 ? shift & 63 : shift & 31;
    if (n === 0) return;
    if (sf === 1) {
      if (n < 32) this.e(`rhi=(rhi<<${n})|(rlo>>>(32-${n}));rlo=rlo<<${n};`);
      else if (n === 32) this.e('rhi=rlo;rlo=0;');
      else this.e(`rhi=rlo<<${n - 32};rlo=0;`);
    } else this.e(`rlo=rlo<<${n};rhi=0;`);
  }

  /** rlo/rhi = rlo/rhi ± b（b 为表达式），setF 时写 cpu.nzcv */
  private emitAddsub(sf: number, sub: boolean, setF: boolean, bLo: string, bHi: string): void {
    const u = this.u++;
    if (sf === 1) {
      if (sub) {
        this.e(`let a${u}=rlo,a${u}h=rhi,d${u}=(a${u}>>>0)-(${bLo}>>>0),` +
          `h${u}=(a${u}h>>>0)-(${bHi}>>>0)-(d${u}<0?1:0);rlo=d${u}|0;rhi=h${u}|0;`);
        if (setF) {
          this.e(`cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2)|(h${u}<0?0:2)|` +
            `((((a${u}h^(${bHi}))&(a${u}h^rhi))>>>31)&1);`);
        }
      } else {
        this.e(`let a${u}=rlo,a${u}h=rhi,s${u}=(a${u}>>>0)+(${bLo}>>>0),` +
          `h${u}=(a${u}h>>>0)+(${bHi}>>>0)+(s${u}>4294967295?1:0);rlo=s${u}|0;rhi=h${u}|0;`);
        if (setF) {
          this.e(`cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2)|(h${u}>4294967295?2:0)|` +
            `(((~((a${u}h)^(${bHi}))&((a${u}h)^rhi))>>>31)&1);`);
        }
      }
      return;
    }
    if (sub) {
      this.e(`let a${u}=rlo,d${u}=(a${u}>>>0)-(${bLo}>>>0);rlo=d${u}|0;rhi=0;`);
      if (setF) {
        this.e(`cpu.nzcv=((rlo>>>31)<<3)|((rlo===0?1:0)<<2)|(d${u}<0?0:2)|` +
          `((((a${u}^(${bLo}))&(a${u}^rlo))>>>31)&1);`);
      }
    } else {
      this.e(`let a${u}=rlo,s${u}=(a${u}>>>0)+(${bLo}>>>0);rlo=s${u}|0;rhi=0;`);
      if (setF) {
        this.e(`cpu.nzcv=((rlo>>>31)<<3)|((rlo===0?1:0)<<2)|(s${u}>4294967295?2:0)|` +
          `(((~((a${u})^(${bLo}))&((a${u})^rlo))>>>31)&1);`);
      }
    }
  }

  /** rlo/rhi = 从 rlo/rhi 中按位域取 width 位（offset/width 为立即数） */
  private emitExtract(offset: number, width: number): void {
    if (offset === 0) {
      // 原样
    } else if (offset < 32) {
      this.e(`rlo=(rlo>>>${offset})|(rhi<<${32 - offset});rhi=rhi>>>${offset};`);
    } else if (offset === 32) {
      this.e('rlo=rhi;rhi=0;');
    } else {
      this.e(`rlo=rhi>>>${offset - 32};rhi=0;`);
    }
    if (width < 32) this.e(`rlo=rlo&${(1 << width) - 1};rhi=0;`);
    else if (width === 32) this.e('rhi=0;');
    else if (width < 64) this.e(`rhi=rhi&${(1 << (width - 32)) - 1};`);
  }

  /** num(r)：含 sp 的 64 位地址表达式（高 32 位为 0 时跳过浮点乘法） */
  private numExpr(r: number): string {
    return `(XHI[${r}]===0?XLO[${r}]>>>0:XHI[${r}]*4294967296+(XLO[${r}]>>>0))`;
  }

  /** 取页（顺带保证已分配），返回 [地址变量, DataView 变量] */
  private pageOf(addrExpr: string): [string, string] {
    const u = this.u++;
    this.e(`let A${u}=${addrExpr},P${u}=DV[A${u}>>>16];` +
      `if(P${u}===undefined)P${u}=MEM.mkdv(A${u});`);
    return [`A${u}`, `P${u}`];
  }

  /** 读 bytes ∈ {1,2,4,8} 字节，返回 [lo, hi] 变量名 */
  private emitLoad(bytes: number, A: string, P: string): [string, string] {
    const u = this.u++;
    const o = `o${u}`;
    if (bytes === 8) {
      this.e(`let ${o}=${A}&65535,l${u}=0,h${u}=0;` +
        `if(${o}>65528){l${u}=MEM.ld64(${A},T1);h${u}=T1[0];}` +
        `else{l${u}=${P}.getUint32(${o},true)|0;h${u}=${P}.getUint32(${o}+4,true)|0;}`);
      return [`l${u}`, `h${u}`];
    }
    if (bytes === 4) {
      this.e(`let ${o}=${A}&65535,v${u}=${o}>65532?MEM.ld32(${A}):${P}.getUint32(${o},true)|0;`);
    } else if (bytes === 2) {
      this.e(`let ${o}=${A}&65535,v${u}=${o}>65534?MEM.ld16(${A}):${P}.getUint16(${o},true)|0;`);
    } else {
      this.e(`let v${u}=${P}.getUint8(${A}&65535);`);
    }
    return [`v${u}`, '0'];
  }

  /** 写 bytes ∈ {1,2,4,8} 字节 */
  private emitStore(bytes: number, A: string, P: string, lo: string, hi: string): void {
    const u = this.u++;
    const o = `o${u}`;
    if (bytes === 8) {
      this.e(`let ${o}=${A}&65535,s${u}=${lo},t${u}=${hi};` +
        `if(${o}>65528)MEM.st64(${A},s${u},t${u});else{` +
        `${P}.setUint32(${o},s${u},true);${P}.setUint32(${o}+4,t${u},true);}`);
      return;
    }
    if (bytes === 4) {
      this.e(`let ${o}=${A}&65535,v${u}=${lo};if(${o}>65532)MEM.st32(${A},v${u});` +
        `else ${P}.setUint32(${o},v${u},true);`);
    } else if (bytes === 2) {
      this.e(`let ${o}=${A}&65535,v${u}=${lo};if(${o}>65534)MEM.st16(${A},v${u});` +
        `else ${P}.setUint16(${o},v${u},true);`);
    } else {
      this.e(`MEM.st8(${A},${lo});`);
    }
  }

  private emitLoadAt(bytes: number, addrExpr: string): [string, string] {
    const [A, P] = this.pageOf(addrExpr);
    return this.emitLoad(bytes, A, P);
  }

  private emitStoreAt(bytes: number, addrExpr: string, lo: string, hi: string): void {
    const [A, P] = this.pageOf(addrExpr);
    this.emitStore(bytes, A, P, lo, hi);
  }

  /** 单寄存器访存（与 cpu.ldstOneN 等价） */
  private emitLdstOne(w: number, addrExpr: string): void {
    const size = w >>> 30;
    const V = (w >>> 26) & 1;
    const opc = (w >>> 22) & 3;
    const rt = w & 31;
    if (V === 1) {
      const k = rt * 4;
      if (size === 0 && opc >= 2) {
        if (opc === 2) {
          this.emitStoreAt(8, addrExpr, `VI[${k}]`, `VI[${k + 1}]`);
          this.emitStoreAt(8, `(${addrExpr}+8)`, `VI[${k + 2}]`, `VI[${k + 3}]`);
        } else {
          const [l0, h0] = this.emitLoadAt(8, addrExpr);
          const [l1, h1] = this.emitLoadAt(8, `(${addrExpr}+8)`);
          this.e(`VI[${k}]=${l0};VI[${k + 1}]=${h0};VI[${k + 2}]=${l1};VI[${k + 3}]=${h1};`);
        }
        return;
      }
      const bytes = 1 << size;
      if (opc === 0) {
        this.emitStoreAt(bytes, addrExpr, `VI[${k}]`, `VI[${k + 1}]`);
        return;
      }
      if (opc !== 1) return;
      const [l, h] = this.emitLoadAt(bytes, addrExpr);
      this.e(`VI[${k}]=${l};VI[${k + 1}]=${h};VI[${k + 2}]=0;VI[${k + 3}]=0;`);
      return;
    }
    if (opc === 0) {
      this.emitStoreAt(size === 3 ? 8 : 1 << size, addrExpr, this.rl(rt), this.rh(rt));
      return;
    }
    if (opc === 1) {
      const [l, h] = this.emitLoadAt(size === 3 ? 8 : 1 << size, addrExpr);
      if (rt !== 31) this.e(`XLO[${rt}]=${l};XHI[${rt}]=${h};`);
      return;
    }
    if (size === 3) return; // PRFM
    const [l] = this.emitLoadAt(1 << size, addrExpr);
    if (rt === 31) return;
    if (size === 2) this.e(`XLO[${rt}]=${l};XHI[${rt}]=${l}>>31;`);
    else if (size === 1) this.e(`XLO[${rt}]=(${l}<<16)>>16;XHI[${rt}]=0;`);
    else this.e(`XLO[${rt}]=(${l}<<24)>>24;XHI[${rt}]=0;`);
  }

  /** 热类：整数运算与访存 */
  private emitInstr(addr: number, w: number, c: number): boolean {
    if (this.skip !== undefined && this.skip.has(c)) return this.emitFallback(addr, w, c);
    switch (c) {
      case C_MOVEWIDE: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const shift = ((w >>> 21) & 3) * 16;
        const imm = (w >>> 5) & 0xffff;
        const rd = w & 31;
        if (rd === 31) return true;
        if (opc === 2) {
          if (shift < 32) this.e(`XLO[${rd}]=${imm}<<${shift};XHI[${rd}]=0;`);
          else this.e(`XLO[${rd}]=0;XHI[${rd}]=${imm}<<${shift - 32};`);
        } else if (opc === 0) {
          // MOVN：高位是 ~(imm 溢出的那部分)，shift=16 时并不是 -1
          if (shift < 32) {
            const hi = shift === 0 ? '-1' : `~(${imm}>>>${32 - shift})`;
            this.e(`XLO[${rd}]=~(${imm}<<${shift});XHI[${rd}]=${sf === 1 ? hi : '0'};`);
          } else this.e(`XLO[${rd}]=-1;XHI[${rd}]=~(${imm}<<${shift - 32});`);
        } else if (opc === 3) {
          // MOVK：掩码按 16 位字段算，不能用 imm
          const s = shift < 32 ? shift : shift - 32;
          const m = `~(${0xffff}<<${s})`;
          if (shift < 32) {
            this.e(`XLO[${rd}]=(XLO[${rd}]&${m})|(${imm}<<${shift});` +
              (sf === 1 ? '' : `XHI[${rd}]=0;`));
          } else {
            this.e(`XHI[${rd}]=(XHI[${rd}]&${m})|(${imm}<<${s});`);
          }
        } else return this.emitFallback(addr, w, c);
        return true;
      }
      case C_LOGIC_IMM: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const bm = this.cpu as unknown as {
          decodeBitMasksNum(n: number, imms: number, immr: number, s: number): void;
          bmLo: number; bmHi: number;
        };
        bm.decodeBitMasksNum((w >>> 22) & 1, (w >>> 10) & 0x3f, (w >>> 16) & 0x3f, sf);
        const bmLo = bm.bmLo;
        const bmHi = bm.bmHi;
        this.e(`rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : '0'};`);
        if (opc === 3) {
          this.e(`rlo=rlo&${bmLo};rhi=rhi&${bmHi};` +
            `cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2);`);
          this.wr32(rd, 'rlo');
          return true;
        }
        if (opc === 0) this.e(`rlo=rlo&${bmLo};rhi=rhi&${bmHi};`);
        else if (opc === 1) this.e(`rlo=rlo|${bmLo};rhi=rhi|${bmHi};`);
        else this.e(`rlo=rlo^${bmLo};rhi=rhi^${bmHi};`);
        this.wr64(rd, 'rlo', sf === 1 ? 'rhi' : '0');
        return true;
      }
      case C_LOGIC_SHIFT: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
        this.emitShift(sf, (w >>> 22) & 3, (w >>> 10) & 0x3f);
        if (((w >>> 21) & 1) === 1) this.e(sf === 1 ? 'rlo=~rlo;rhi=~rhi;' : 'rlo=~rlo;');
        const u = this.u++;
        this.e(`let b${u}=rlo,c${u}=${sf === 1 ? 'rhi' : '0'};` +
          `rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : '0'};`);
        if (opc === 3) {
          this.e(`rlo=rlo&b${u};rhi=rhi&c${u};` +
            `cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2);`);
          this.wr32(rd, 'rlo');
          return true;
        }
        if (opc === 0) this.e(`rlo=rlo&b${u};rhi=rhi&c${u};`);
        else if (opc === 1) this.e(`rlo=rlo|b${u};rhi=rhi|c${u};`);
        else this.e(`rlo=rlo^b${u};rhi=rhi^c${u};`);
        this.wr64(rd, 'rlo', sf === 1 ? 'rhi' : '0');
        return true;
      }
      case C_ADDSUB_IMM: {
        const sf = w >>> 31;
        const setF = ((w >>> 29) & 1) === 1;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const imm = ((w >>> 10) & 0xfff) << (((w >>> 22) & 1) === 1 ? 12 : 0);
        this.e(`rlo=XLO[${rn}];rhi=XHI[${rn}];`);
        this.emitAddsub(sf, ((w >>> 30) & 1) === 1, setF, String(imm), '0');
        this.wrAddsub(rd, sf, setF);
        return true;
      }
      case C_ADDSUB_SHIFT: {
        const sf = w >>> 31;
        const setF = ((w >>> 29) & 1) === 1;
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
        this.emitShift(sf, (w >>> 22) & 3, (w >>> 10) & 0x3f);
        const u = this.u++;
        this.e(`let b${u}=rlo,c${u}=${sf === 1 ? 'rhi' : '0'};` +
          `rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : '0'};`);
        this.emitAddsub(sf, ((w >>> 30) & 1) === 1, setF, `b${u}`, `c${u}`);
        // 移位寄存器形式：rd=31 是 XZR（与立即数形式不同）
        if (setF && sf === 0) this.wr32(rd, 'rlo');
        else this.wr64(rd, 'rlo', 'rhi');
        return true;
      }
      case C_ADDSUB_EXT: {
        const sf = w >>> 31;
        const setF = ((w >>> 29) & 1) === 1;
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
        this.emitExtend((w >>> 13) & 7, (w >>> 10) & 7, sf);
        const u = this.u++;
        // 扩展寄存器形式：rn=31 是 SP
        this.e(`let b${u}=rlo,c${u}=${sf === 1 ? 'rhi' : '0'};` +
          `rlo=XLO[${rn}];rhi=${sf === 1 ? `XHI[${rn}]` : '0'};`);
        this.emitAddsub(sf, ((w >>> 30) & 1) === 1, setF, `b${u}`, `c${u}`);
        this.wrAddsub(rd, sf, setF);
        return true;
      }
      case C_BITFIELD: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const immr = (w >>> 16) & 0x3f;
        const imms = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const dsz = sf === 1 ? 64 : 32;
        const width = imms >= immr ? imms - immr + 1 : imms + 1;
        const lsb = imms >= immr ? 0 : dsz - immr;
        this.e(`rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : '0'};`);
        this.emitExtract(imms >= immr ? immr : 0, width);
        if (opc === 0 && width < dsz) {
          if (width < 32) {
            this.e(`if((rlo>>>${width - 1})&1){rlo=rlo|${~((1 << width) - 1)};rhi=-1;}`);
          } else if (width === 32) this.e('if((rlo>>>31)&1)rhi=-1;');
          else this.e(`if((rhi>>>${width - 33})&1){rhi=rhi|${~((1 << (width - 32)) - 1)};}`);
        }
        this.emitShift(sf, 0, lsb);
        if (opc === 0 || opc === 2) {
          this.wr64(rd, 'rlo', 'rhi');
          return true;
        }
        let mLo = 0;
        let mHi = 0;
        if (lsb < 32) {
          const loBits = Math.min(width, 32 - lsb);
          mLo = loBits >= 32 ? -1 : ((1 << loBits) - 1) << lsb;
          if (width > loBits) {
            const hiBits = width - loBits;
            mHi = hiBits >= 32 ? -1 : (1 << hiBits) - 1;
          }
        } else {
          const hiBits = Math.min(width, 64 - lsb);
          mHi = hiBits >= 32 ? -1 : ((1 << hiBits) - 1) << (lsb - 32);
        }
        if (rd !== 31) {
          this.e(`XLO[${rd}]=rlo|(XLO[${rd}]&${~mLo});` +
            `XHI[${rd}]=${sf === 1 ? `rhi|(XHI[${rd}]&${~mHi})` : '0'};`);
        }
        return true;
      }
      case C_EXTR: {
        const sf = w >>> 31;
        const rm = (w >>> 16) & 31;
        const lsb = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const u = this.u++;
        this.e(`let b${u}=${this.rl(rm)},c${u}=${this.rh(rm)},` +
          `a${u}=${this.rl(rn)},d${u}=${this.rh(rn)};`);
        if (sf === 0) {
          const n = lsb & 31;
          this.e(n === 0 ? `rlo=b${u};rhi=0;`
            : `rlo=(b${u}>>>${n})|(a${u}<<${32 - n});rhi=0;`);
        } else if (lsb === 0) this.e(`rlo=b${u};rhi=c${u};`);
        else if (lsb < 32) {
          this.e(`rlo=(b${u}>>>${lsb})|(c${u}<<${32 - lsb});` +
            `rhi=(c${u}>>>${lsb})|(a${u}<<${32 - lsb});`);
        } else if (lsb === 32) this.e(`rlo=c${u};rhi=a${u};`);
        else {
          const m = lsb - 32;
          this.e(`rlo=(c${u}>>>${m})|(a${u}<<${32 - m});` +
            `rhi=(a${u}>>>${m})|(d${u}<<${32 - m});`);
        }
        this.wr64(rd, 'rlo', 'rhi');
        return true;
      }
      case C_CSEL: {
        // 语义镜像 execFast：cond ? rn : transform(rm)，最后无条件写 rd（含 SP）
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const rm = (w >>> 16) & 31;
        const op2 = (w >>> 10) & 3;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const u = this.u++;
        const t = `c${u}`;
        let els = `rlo=${this.rl(rm)};rhi=${this.rh(rm)};`;
        if (op === 0) {
          if (op2 === 1) {
            els += sf === 1
              ? `let ${t}=(rlo>>>0)+1;rlo=${t}|0;if(${t}>4294967295)rhi=(rhi+1)|0;`
              : `rlo=(rlo+1)|0;`;
          }
        } else if (op2 === 0) {
          els += sf === 1 ? 'rlo=~rlo;rhi=~rhi;' : 'rlo=~rlo;';
        } else if (sf === 1) {
          els += `let ${t}=(rlo>>>0)===0?1:0;rlo=(~rlo+1)|0;rhi=(~rhi+${t})|0;`;
        } else {
          els += 'rlo=(~rlo+1)|0;';
        }
        this.e(`if(${this.condExpr((w >>> 12) & 0xf)}){rlo=${this.rl(rn)};rhi=${this.rh(rn)};}` +
          `else{${els}}`);
        this.e(`XLO[${rd}]=rlo|0;XHI[${rd}]=${sf === 1 ? 'rhi' : '0'}|0;`);
        return true;
      }
      case C_PAIR: {
        // 镜像 cpu.ldstPairN：写回放在访存之后（rn 与 rt 相同时以写回为准）
        const opc = w >>> 30;
        const V = (w >>> 26) & 1;
        const L = (w >>> 22) & 1;
        const idx = (w >>> 23) & 3;
        const rn = (w >>> 5) & 31;
        const rt = w & 31;
        const rt2 = (w >>> 10) & 31;
        const bytes = V === 1 ? 4 << opc : (opc === 2 ? 8 : 4);
        const imm = (((w >>> 15) & 0x7f) << 25 >> 25) * bytes;
        const u = this.u++;
        const p = `p${u}`;
        this.e(`let ${p}=${this.numExpr(rn)}${idx === 1 ? '' : `+${imm}`};`);
        if (L === 1) {
          if (V === 1) {
            const k = rt * 4;
            const k2 = rt2 * 4;
            if (bytes === 16) {
              const [l0, h0] = this.emitLoadAt(8, p);
              const [l1, h1] = this.emitLoadAt(8, `(${p}+8)`);
              const [l2, h2] = this.emitLoadAt(8, `(${p}+16)`);
              const [l3, h3] = this.emitLoadAt(8, `(${p}+24)`);
              this.e(`VI[${k}]=${l0};VI[${k + 1}]=${h0};VI[${k + 2}]=${l1};VI[${k + 3}]=${h1};` +
                `VI[${k2}]=${l2};VI[${k2 + 1}]=${h2};VI[${k2 + 2}]=${l3};VI[${k2 + 3}]=${h3};`);
            } else if (bytes === 8) {
              const [l0, h0] = this.emitLoadAt(8, p);
              const [l1, h1] = this.emitLoadAt(8, `(${p}+8)`);
              this.e(`VI[${k}]=${l0};VI[${k + 1}]=${h0};VI[${k + 2}]=0;VI[${k + 3}]=0;` +
                `VI[${k2}]=${l1};VI[${k2 + 1}]=${h1};VI[${k2 + 2}]=0;VI[${k2 + 3}]=0;`);
            } else {
              const [l0] = this.emitLoadAt(4, p);
              const [l1] = this.emitLoadAt(4, `(${p}+4)`);
              this.e(`VI[${k}]=${l0};VI[${k + 1}]=0;VI[${k + 2}]=0;VI[${k + 3}]=0;` +
                `VI[${k2}]=${l1};VI[${k2 + 1}]=0;VI[${k2 + 2}]=0;VI[${k2 + 3}]=0;`);
            }
          } else if (bytes === 8) {
            const [l0, h0] = this.emitLoadAt(8, p);
            const [l1, h1] = this.emitLoadAt(8, `(${p}+8)`);
            if (rt !== 31) this.e(`XLO[${rt}]=${l0};XHI[${rt}]=${h0};`);
            if (rt2 !== 31) this.e(`XLO[${rt2}]=${l1};XHI[${rt2}]=${h1};`);
          } else {
            const [l0] = this.emitLoadAt(4, p);
            const [l1] = this.emitLoadAt(4, `(${p}+4)`);
            const sx = opc === 1;
            if (rt !== 31) this.e(`XLO[${rt}]=${l0};XHI[${rt}]=${sx ? `${l0}>>31` : '0'};`);
            if (rt2 !== 31) this.e(`XLO[${rt2}]=${l1};XHI[${rt2}]=${sx ? `${l1}>>31` : '0'};`);
          }
        } else if (V === 1) {
          const k = rt * 4;
          const k2 = rt2 * 4;
          if (bytes === 16) {
            this.emitStoreAt(8, p, `VI[${k}]`, `VI[${k + 1}]`);
            this.emitStoreAt(8, `(${p}+8)`, `VI[${k + 2}]`, `VI[${k + 3}]`);
            this.emitStoreAt(8, `(${p}+16)`, `VI[${k2}]`, `VI[${k2 + 1}]`);
            this.emitStoreAt(8, `(${p}+24)`, `VI[${k2 + 2}]`, `VI[${k2 + 3}]`);
          } else if (bytes === 8) {
            this.emitStoreAt(8, p, `VI[${k}]`, `VI[${k + 1}]`);
            this.emitStoreAt(8, `(${p}+8)`, `VI[${k2}]`, `VI[${k2 + 1}]`);
          } else {
            this.emitStoreAt(4, p, `VI[${k}]`, '0');
            this.emitStoreAt(4, `(${p}+4)`, `VI[${k2}]`, '0');
          }
        } else if (bytes === 8) {
          this.emitStoreAt(8, p, this.rl(rt), this.rh(rt));
          this.emitStoreAt(8, `(${p}+8)`, this.rl(rt2), this.rh(rt2));
        } else {
          this.emitStoreAt(4, p, this.rl(rt), '0');
          this.emitStoreAt(4, `(${p}+4)`, this.rl(rt2), '0');
        }
        if (idx === 1) {
          this.e(`XLO[${rn}]=(${p}+${imm})|0;` +
            `XHI[${rn}]=Math.floor((${p}+${imm})/4294967296)|0;`);
        } else if (idx === 3) {
          this.e(`XLO[${rn}]=${p}|0;XHI[${rn}]=Math.floor(${p}/4294967296)|0;`);
        }
        return true;
      }
      case C_DP2: {
        // 32 位：纯 number；64 位：移位用字运算、除法则用 BigInt
        const sf = w >>> 31;
        const rm = (w >>> 16) & 31;
        const opcode = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        if (rd === 31) return true;
        const u = this.u++;
        const n = `n${u}`;
        if (opcode === 2 || opcode === 3) {
          const a = this.rl(rn);
          const b = this.rl(rm);
          if (sf === 0) {
            const q = `q${u}`;
            const div = opcode === 2 ? `((${a}>>>0)/(${q}>>>0))|0` : `((${a}|0)/${q})|0`;
            this.e(`let ${q}=${b}|0;XHI[${rd}]=0;` +
              `XLO[${rd}]=${q}===0?0:(${div});`);
          } else {
            const A = `A${u}`;
            const B = `B${u}`;
            const R = `R${u}`;
            this.e(`let ${A}=(BigInt(${this.rh(rn)}>>>0)<<32n)|BigInt(${a}>>>0),` +
              `${B}=(BigInt(${this.rh(rm)}>>>0)<<32n)|BigInt(${b}>>>0);`);
            if (opcode === 2) {
              this.e(`let ${R}=${B}===0n?0n:(${A}/${B});`);
            } else {
              this.e(`let ${R}=${B}===0n?0n:BigInt.asUintN(64,BigInt.asIntN(64,${A})/` +
                `BigInt.asIntN(64,${B}));`);
            }
            this.e(`XLO[${rd}]=Number(${R}&0xffffffffn)|0;XHI[${rd}]=Number(${R}>>32n)|0;`);
          }
          return true;
        }
        if (opcode < 8 || opcode > 11) return this.emitFallback(addr, w, c);
        const type = opcode - 8;
        const a = this.rl(rn);
        const ah = this.rh(rn);
        if (sf === 0) {
          this.e(`let ${n}=${this.rl(rm)}&31;`);
          if (type === 0) this.e(`XLO[${rd}]=(${a}<<${n})|0;XHI[${rd}]=0;`);
          else if (type === 1) this.e(`XLO[${rd}]=(${a}>>>${n})|0;XHI[${rd}]=0;`);
          else if (type === 2) this.e(`XLO[${rd}]=(${a}>>${n})|0;XHI[${rd}]=0;`);
          else this.e(`XLO[${rd}]=((${a}>>>${n})|(${a}<<(32-${n})))|0;XHI[${rd}]=0;`);
          return true;
        }
        this.e(`let ${n}=${this.rl(rm)}&63;`);
        const lo = `l${u}`;
        const hi = `h${u}`;
        if (type === 0) {
          this.e(`let ${lo}=${a},${hi}=${ah};` +
            `if(${n}===0){}else if(${n}<32){${hi}=(${hi}<<${n})|(${lo}>>>(32-${n}));${lo}=${lo}<<${n};}` +
            `else if(${n}===32){${hi}=${lo};${lo}=0;}else{${hi}=${lo}<<(${n}-32);${lo}=0;}`);
        } else if (type === 1) {
          this.e(`let ${lo}=${a},${hi}=${ah};` +
            `if(${n}===0){}else if(${n}<32){${lo}=(${lo}>>>${n})|(${hi}<<(32-${n}));` +
            `${hi}=${hi}>>>${n};}else if(${n}===32){${lo}=${hi};${hi}=0;}` +
            `else{${lo}=${hi}>>>(${n}-32);${hi}=0;}`);
        } else if (type === 2) {
          this.e(`let ${lo}=${a},${hi}=${ah};` +
            `if(${n}===0){}else if(${n}<32){${lo}=(${lo}>>>${n})|(${hi}<<(32-${n}));` +
            `${hi}=${hi}>>${n};}else if(${n}===32){${lo}=${hi};${hi}=${hi}>>31;}` +
            `else{${lo}=${hi}>>(${n}-32);${hi}=${hi}>>31;}`);
        } else {
          this.e(`let ${lo}=${a},${hi}=${ah};` +
            `if(${n}===0){}else if(${n}<32){let t${u}=${lo};` +
            `${lo}=(${lo}>>>${n})|(${hi}<<(32-${n}));${hi}=(${hi}>>>${n})|(t${u}<<(32-${n}));}` +
            `else if(${n}===32){let t${u}=${lo};${lo}=${hi};${hi}=t${u};}` +
            `else{let t${u}=${lo};${lo}=(${hi}>>>(${n}-32))|(${lo}<<(32-(${n}-32)));` +
            `${hi}=(t${u}>>>(${n}-32))|(${hi}<<(32-(${n}-32)));}`);
        }
        this.e(`XLO[${rd}]=${lo}|0;XHI[${rd}]=${hi}|0;`);
        return true;
      }
      case C_ADR: {
        const imm = (((w >> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
        const off = (imm << 11) >> 11;
        const v = (w >>> 31) === 1 ? (addr & ~0xfff) + off * 4096 : addr + off;
        this.wr64(w & 31, String(v | 0), String(Math.floor(v / 4294967296) | 0));
        return true;
      }
      case C_LDST_UOFF: {
        const rn = (w >>> 5) & 31;
        const bytes = this.ldstBytes(w);
        this.emitLdstOne(w, `(${this.numExpr(rn)}+${((w >>> 10) & 0xfff) * bytes})`);
        return true;
      }
      case C_LDST_UNSCALED: {
        const rn = (w >>> 5) & 31;
        const off = (((w >>> 12) & 0x1ff) << 23) >> 23;
        this.emitLdstOne(w, `(${this.numExpr(rn)}+${off})`);
        return true;
      }
      case C_LDST_PRE: {
        // execFast：base = num(rn)+off; sxNumS(rn, base); ldstOneN(w, base)
        const rn = (w >>> 5) & 31;
        const off = (((w >>> 12) & 0x1ff) << 23) >> 23;
        const u = this.u++;
        this.e(`let n${u}=${this.numExpr(rn)}+${off};` +
          `XLO[${rn}]=n${u}|0;XHI[${rn}]=Math.floor(n${u}/4294967296)|0;`);
        this.emitLdstOne(w, `n${u}`);
        return true;
      }
      case C_LDST_POST: {
        // execFast：base = num(rn); ldstOneN(w, base); sxNumS(rn, base+off)
        const rn = (w >>> 5) & 31;
        const off = (((w >>> 12) & 0x1ff) << 23) >> 23;
        const u = this.u++;
        this.e(`let n${u}=${this.numExpr(rn)};`);
        this.emitLdstOne(w, `n${u}`);
        this.e(`XLO[${rn}]=(n${u}+${off})|0;` +
          `XHI[${rn}]=Math.floor((n${u}+${off})/4294967296)|0;`);
        return true;
      }
      case C_LDST_LIT: {
        const off = (((w >>> 5) & 0x7ffff) << 13) >> 13;
        this.emitLdstOne(w, `(${addr + 4 + off * 4})`);
        return true;
      }
      case C_LDST_ROFF: {
        const size = w >>> 30;
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const bytes = this.ldstBytes(w);
        const shift = ((w >>> 12) & 1) === 1 ? (bytes === 16 ? 4 : size) : 0;
        this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
        this.emitExtend((w >>> 13) & 7, shift, 1);
        const u = this.u++;
        this.e(`let r${u}=rhi*4294967296+(rlo>>>0);`);
        this.emitLdstOne(w, `(${this.numExpr(rn)}+r${u})`);
        return true;
      }
      default:
        return this.emitOther(addr, w, c);
    }
  }

  /** ldstBytes：SIMD 128 位（V=1,size=0,opc>=2）按 16 字节算 */
  private ldstBytes(w: number): number {
    return ((w >>> 26) & 1) === 1 && (w >>> 30) === 0 && ((w >>> 22) & 3) >= 2
      ? 16
      : 1 << (w >>> 30);
  }

  /** 条件码 → JS 布尔表达式（与 cpu.cond 等价，编译期展开） */
  private condExpr(c: number): string {
    if (c >= 14) return 'true';
    const n = '((cpu.nzcv&8)!==0)';
    const z = '((cpu.nzcv&4)!==0)';
    const cy = '((cpu.nzcv&2)!==0)';
    const v = '((cpu.nzcv&1)!==0)';
    let r: string;
    switch (c >> 1) {
      case 0: r = z; break;
      case 1: r = cy; break;
      case 2: r = n; break;
      case 3: r = v; break;
      case 4: r = `(${cy}&&!${z})`; break;
      case 5: r = `(${n}===${v})`; break;
      case 6: r = `(${n}===${v}&&!${z})`; break;
      default: r = 'true'; break;
    }
    return (c & 1) !== 0 ? `(!${r})` : r;
  }

  /** SO_JITSTAT：记录每块执行次数与源码（调优用） */
  static readonly STAT = !!process.env.SO_JITSTAT;

  /** 控制流类：块必须在此结束 */
  private static readonly CF = new Set<number>([
    C_SVC, C_BRK, C_BBL, C_BCOND, C_CBZ, C_TBZ, C_BR, C_BLR, C_RET,
  ]);

  /** 回退：把这条指令交给解释器执行（非控制流类可继续块内后续指令） */
  private emitFallback(addr: number, w: number, c: number): boolean {
    this.e(`cpu.pc=${addr + 4};cpu.exec(${c},${w});`);
    if (Jit.CF.has(c)) {
      this.e('return;');
      return false;
    }
    return true;
  }

  /** 其余指令类：控制流 / 向量 / 空操作 */
  private emitOther(addr: number, w: number, c: number): boolean {
    switch (c) {
      case C_BBL: {
        const off = ((w & 0x3ffffff) << 6) >> 6;
        if ((w >>> 31) === 1) this.wr64(30, String(addr + 4), '0');
        this.e(`cpu.pc=${addr + off * 4};return;`);
        return false;
      }
      case C_BCOND: {
        const off = (((w >>> 5) & 0x7ffff) << 13) >> 13;
        this.e(`cpu.pc=${addr + 4};if(${this.condExpr(w & 0xf)})cpu.pc=${addr + off * 4};return;`);
        return false;
      }
      case C_CBZ: {
        const rt = w & 31;
        const sf = w >>> 31;
        const nz = (w >>> 24) & 1;
        const off = (((w >>> 5) & 0x7ffff) << 13) >> 13;
        const v = rt === 31 ? '0' : sf === 1 ? `(XLO[${rt}]|XHI[${rt}])` : `XLO[${rt}]`;
        const test = nz === 1 ? `(${v})!==0` : `(${v})===0`;
        this.e(`cpu.pc=${addr + 4};if(${test})cpu.pc=${addr + off * 4};return;`);
        return false;
      }
      case C_TBZ: {
        const bit = (((w >>> 31) & 1) << 5) | ((w >>> 19) & 0x1f);
        const rt = w & 31;
        const nz = (w >>> 24) & 1;
        const off = (((w >>> 5) & 0x3fff) << 18) >> 18;
        const v = rt === 31
          ? '0'
          : bit < 32 ? `((XLO[${rt}]>>>${bit})&1)` : `((XHI[${rt}]>>>${bit - 32})&1)`;
        this.e(`cpu.pc=${addr + 4};if((${v})===${nz})cpu.pc=${addr + off * 4};return;`);
        return false;
      }
      case C_BR: {
        this.e(`cpu.pc=${this.numExpr((w >>> 5) & 31)};return;`);
        return false;
      }
      case C_BLR: {
        // 先取目标再写 X30，blr x30 才是跳旧值（与 cpu.execFast 一致）
        this.e(`cpu.pc=${this.numExpr((w >>> 5) & 31)};`);
        this.wr64(30, String(addr + 4), '0');
        this.e('return;');
        return false;
      }
      case C_RET: {
        this.e(`cpu.pc=${this.numExpr((w >>> 5) & 31)};return;`);
        return false;
      }
      case C_VEC_LOGIC: {
        const Q = (w >>> 30) & 1;
        const op = (((w >>> 29) & 1) << 2) | ((w >>> 22) & 3);
        const k = (w & 31) * 4;
        const an = ((w >>> 5) & 31) * 4;
        const am = ((w >>> 16) & 31) * 4;
        for (let i = 0; i < 4; i++) {
          const a = `VI[${an + i}]`;
          const b = `VI[${am + i}]`;
          const d = `VI[${k + i}]`;
          let s: string;
          if (op === 0) s = `${a}&${b}`;
          else if (op === 1) s = `${a}&~${b}`;
          else if (op === 2) s = `${a}|${b}`;
          else if (op === 3) s = `${a}|~${b}`;
          else if (op === 4) s = `${a}^${b}`;
          else if (op === 5 || op === 6) s = `(${a}&${b})|(~${a}&${d})`;
          else s = `(${a}&${d})|(~${a}&${b})`;
          this.e(`${d}=${s};`);
        }
        if (Q !== 1) this.e(`VI[${k + 2}]=0;VI[${k + 3}]=0;`);
        return true;
      }
      case C_VEC_UMOV: {
        const Q = (w >>> 30) & 1;
        const imm5 = (w >>> 16) & 0x1f;
        const low = imm5 & -imm5;
        const sz = 31 - Math.clz32(low);
        const esize = 8 << sz;
        const index = imm5 >> (sz + 1);
        const bit = index * esize;
        const k = ((w >>> 5) & 31) * 4 + (bit >>> 5);
        const rd = w & 31;
        if (rd === 31) return true;
        if (esize === 64) {
          this.e(`XLO[${rd}]=VI[${k}];XHI[${rd}]=${Q === 1 ? `VI[${k + 1}]` : '0'};`);
          return true;
        }
        const sh = bit & 31;
        let v: string;
        if (sh === 0) v = `VI[${k}]`;
        else v = `(VI[${k}]>>>${sh})|(VI[${k + 1}]<<${32 - sh})`;
        if (esize === 32) this.e(`XLO[${rd}]=${v}|0;XHI[${rd}]=0;`);
        else if (esize === 16) this.e(`XLO[${rd}]=(${v})&65535;XHI[${rd}]=0;`);
        else this.e(`XLO[${rd}]=(${v})&255;XHI[${rd}]=0;`);
        return true;
      }
      case C_VEC_ZIP1:
        this.e(`cpu.vzipN(${w},true);`);
        return true;
      case C_VEC_UZP1:
        this.e(`cpu.vzipN(${w},false);`);
        return true;
      case C_VEC_EXT:
        this.e(`cpu.vextN(${w});`);
        return true;
      case C_VEC_USHL:
        this.e(`cpu.vushlN(${w});`);
        return true;
      case C_VEC_DUP_GEN:
        this.e(`cpu.vdupN(${w},false);`);
        return true;
      case C_VEC_DUP_EL:
        this.e(`cpu.vdupN(${w},true);`);
        return true;
      case C_FMOV_WS: {
        const rd = w & 31;
        if (rd !== 31) this.e(`XLO[${rd}]=VI[${((w >>> 5) & 31) * 4}];XHI[${rd}]=0;`);
        return true;
      }
      case C_CLREX:
      case C_PAC:
      case C_XPACLRI:
      case C_BTI:
      case C_HINT:
      case C_BARRIER:
        return true;
      default:
        return this.emitFallback(addr, w, c);
    }
  }
}
