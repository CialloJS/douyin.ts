/**
 * 纯 TS 的 AArch64 解释器（只覆盖 libmetasec_ml.so 实际用到的指令）。
 *
 * 设计取舍：
 * - 地址用 number（映射区间都在 0x4000_0000 附近，远小于 2^53）
 * - 通用寄存器用 BigUint64Array（自动按 64 位截断），index 31 存 sp
 * - 向量寄存器用 BigUint64Array(64)：v[2i] = 低 64 位，v[2i+1] = 高 64 位
 * - 指令字 → 分类 走 Map 缓存，热路径只做一次整数比较
 */
import type { ArmMem } from './mem.js';

const MASK64 = 0xffffffffffffffffn;
const MASK32 = 0xffffffffn;

export const F_N = 8;
export const F_Z = 4;
export const F_C = 2;
export const F_V = 1;

// ---- 分类 id（顺序与 verify_decode.py 一致）----
export const C_CLREX = 1;
export const C_SVC = 2;
export const C_BRK = 3;
export const C_PAC = 4;
export const C_XPACLRI = 5;
export const C_BTI = 6;
export const C_HINT = 7;
export const C_BARRIER = 8;
export const C_MRS = 9;
export const C_MSRREG = 10;
export const C_ADR = 11;
export const C_ADDSUB_IMM = 12;
export const C_LOGIC_IMM = 13;
export const C_MOVEWIDE = 14;
export const C_BITFIELD = 15;
export const C_EXTR = 16;
export const C_BCOND = 17;
export const C_CBZ = 18;
export const C_TBZ = 19;
export const C_BBL = 20;
export const C_BR = 21;
export const C_BLR = 22;
export const C_RET = 23;
export const C_LDAR = 24;
export const C_STLR = 25;
export const C_LDAXR = 26;
export const C_STLXR = 27;
export const C_PAIR = 28;
export const C_LDST_UOFF = 29;
export const C_LDST_ROFF = 30;
export const C_LDST_UNSCALED = 31;
export const C_LDST_POST = 32;
export const C_LDST_PRE = 33;
export const C_LDST_LIT = 34;
export const C_ADDSUB_SHIFT = 35;
export const C_ADDSUB_EXT = 36;
export const C_LOGIC_SHIFT = 37;
export const C_ADDSUB_CARRY = 38;
export const C_CSEL = 39;
export const C_CCMP = 40;
export const C_CCMP_IMM = 41;
export const C_DP2 = 42;
export const C_DP1 = 43;
export const C_DP3 = 44;
export const C_FMOV_IMM = 45;
export const C_FMOV_WS = 46;
export const C_FMOV_XD = 47;
export const C_FMOV_SW = 48;
export const C_FMOV_DX = 49;
export const C_FMOV_DD = 50;
export const C_FMOV_SS = 51;
export const C_FABS_D = 52;
export const C_FABS_S = 53;
export const C_FABD_D = 54;
export const C_FABD_S = 55;
export const C_FMUL_D = 56;
export const C_FMUL_S = 57;
export const C_FCMP_D = 58;
export const C_FCMP_S = 59;
export const C_FCMP_D0 = 60;
export const C_FCMP_S0 = 61;
export const C_FCSEL_D = 62;
export const C_FCSEL_S = 63;
export const C_FCCMP_D = 64;
export const C_FCCMP_S = 65;
export const C_FCVTZS_WD = 66;
export const C_FCVTZS_XD = 67;
export const C_FCVTZU_WD = 114;
export const C_FCVTZU_XD = 115;
export const C_FCVTPU_WS = 116;
export const C_FCVTPU_WD = 117;
export const C_FCVTPU_XS = 118;
export const C_FCVTPU_XD = 119;
export const C_VEC_CNT = 120;
export const C_VEC_UADDLV = 121;
export const C_SCVTF_DW = 68;
export const C_SCVTF_DX = 69;
export const C_UCVTF_DW = 70;
export const C_UCVTF_DX = 71;
export const C_SCVTF_DD = 72;
export const C_UCVTF_DD = 73;
export const C_SCVTF_SS = 74;
export const C_UCVTF_SS = 75;
export const C_VEC_LOGIC = 76;
export const C_VEC_UMOV = 77;
export const C_VEC_DUP_GEN = 78;
export const C_VEC_DUP_EL = 79;
export const C_VEC_MOVI = 80;
export const C_VEC_ZIP1 = 81;
export const C_VEC_UZP1 = 82;
export const C_VEC_EXT = 83;
export const C_VEC_USHL = 84;
export const C_VEC_SSHLL = 85;
export const C_LDXR = 86;
export const C_STXR = 87;
export const C_VEC_SHL_SC = 88;
export const C_FADD_D = 89;
export const C_FADD_S = 90;
export const C_FSUB_D = 91;
export const C_FSUB_S = 92;
export const C_FDIV_D = 93;
export const C_FDIV_S = 94;
export const C_FMADD_D = 95;
export const C_FMADD_S = 96;
export const C_FMSUB_D = 97;
export const C_FMSUB_S = 98;
export const C_FNMADD_D = 99;
export const C_FNMADD_S = 100;
export const C_FNMSUB_D = 101;
export const C_FNMSUB_S = 102;
export const C_FNEG_D = 103;
export const C_FNEG_S = 104;
export const C_FSQRT_D = 105;
export const C_FSQRT_S = 106;
export const C_VEC_SHL_V = 107;
export const C_SCVTF_SW = 108;
export const C_UCVTF_SW = 109;
export const C_SCVTF_SX = 110;
export const C_UCVTF_SX = 111;
export const C_VEC_ADD = 112;
export const C_VEC_SUB = 113;

export const C_UNKNOWN = 0;

/**
 * AdvSIMD modified immediate 的通道表：key = cmode*2 + op。
 * 值 = [通道位数, imm8 左移位数, MSL 补 1 位数, 是否取反(MVNI)]。
 * 语义以 capstone 反汇编核对（cmode 0/2/4/6→32 位，8/a→16 位，c/d→MSL，e→8 位/2D）。
 */
const MOVI_LANES: Record<number, [number, number, number, number]> = {
  0x00: [32, 0, 0, 0], 0x01: [32, 0, 0, 1],
  0x04: [32, 8, 0, 0], 0x05: [32, 8, 0, 1],
  0x08: [32, 16, 0, 0], 0x09: [32, 16, 0, 1],
  0x0c: [32, 24, 0, 0], 0x0d: [32, 24, 0, 1],
  0x10: [16, 0, 0, 0], 0x11: [16, 0, 0, 1],
  0x14: [16, 8, 0, 0], 0x15: [16, 8, 0, 1],
  0x18: [32, 8, 8, 0], 0x19: [32, 8, 8, 1],
  0x1a: [32, 16, 16, 0], 0x1b: [32, 16, 16, 1],
  0x1c: [8, 0, 0, 0], 0x1d: [64, 56, 0, 0],
};

/** 指令字 → 分类 id。掩码顺序敏感，必须与 verify_decode.py 一致。 */
export function classify(w: number): number {
  // 注意：JS 的 & 结果是 int32（有符号），必须 >>>0 后再与无符号字面量比较
  const eq = (mask: number, val: number): boolean => ((w & mask) >>> 0) === val;
  if (w === 0xd5033f5f) return C_CLREX;
  if (eq(0xffe0001f, 0xd4000001)) return C_SVC;
  if (eq(0xffe0001f, 0xd4200000)) return C_BRK;
  if (w === 0xd503233f || w === 0xd50323bf || w === 0xd503235f || w === 0xd50323df) return C_PAC;
  if (w === 0xd50320ff) return C_XPACLRI;
  if (eq(0xffffff1f, 0xd503241f)) return C_BTI;
  if (eq(0xfffff01f, 0xd503201f)) return C_HINT;
  if (eq(0xfffff09f, 0xd503309f)) return C_BARRIER;
  if (eq(0xffe00000, 0xd5200000)) return C_MRS;
  if (eq(0xffe00000, 0xd5000000)) return C_MSRREG;
  if (eq(0x1f000000, 0x10000000)) return C_ADR;
  if (eq(0x1f000000, 0x11000000)) return C_ADDSUB_IMM;
  if (eq(0x1f800000, 0x12000000)) return C_LOGIC_IMM;
  if (eq(0x1f800000, 0x12800000)) return C_MOVEWIDE;
  if (eq(0x1f800000, 0x13000000)) return C_BITFIELD;
  if (eq(0x7f800000, 0x13800000)) return C_EXTR;
  if (eq(0xff000010, 0x54000000)) return C_BCOND;
  if (eq(0x7e000000, 0x34000000)) return C_CBZ;
  if (eq(0x7e000000, 0x36000000)) return C_TBZ;
  if (eq(0x7c000000, 0x14000000)) return C_BBL;
  if (eq(0xfffffc1f, 0xd61f0000)) return C_BR;
  if (eq(0xfffffc1f, 0xd63f0000)) return C_BLR;
  if (eq(0xfffffc1f, 0xd65f0000)) return C_RET;
  if (eq(0x3ffffc00, 0x08dffc00)) return C_LDAR;
  if (eq(0x3ffffc00, 0x089ffc00)) return C_STLR;
  if (eq(0x3ffffc00, 0x085ffc00)) return C_LDAXR;
  if (eq(0x3ffffc00, 0x085f7c00)) return C_LDXR;
  if (eq(0x3fe0fc00, 0x0800fc00)) return C_STLXR;
  if (eq(0x3fe0fc00, 0x08007c00)) return C_STXR;
  if (eq(0x3a000000, 0x28000000)) return C_PAIR;
  if (eq(0x3b000000, 0x39000000)) return C_LDST_UOFF;
  if (eq(0x3b200800, 0x38200800)) return C_LDST_ROFF;
  if (eq(0x3b200c00, 0x38000000)) return C_LDST_UNSCALED;
  if (eq(0x3b200c00, 0x38000400)) return C_LDST_POST;
  if (eq(0x3b200c00, 0x38000c00)) return C_LDST_PRE;
  if (eq(0x3b000000, 0x18000000)) return C_LDST_LIT;
  if (eq(0x1f200000, 0x0b000000)) return C_ADDSUB_SHIFT;
  if (eq(0x1f200000, 0x0b200000)) return C_ADDSUB_EXT;
  if (eq(0x1f000000, 0x0a000000)) return C_LOGIC_SHIFT;
  if (eq(0x1fe00000, 0x1a000000)) return C_ADDSUB_CARRY;
  if (eq(0x1fe00000, 0x1a800000)) return C_CSEL;
  if (eq(0x1fe00800, 0x1a400000)) return C_CCMP;
  if (eq(0x1fe00800, 0x1a400800)) return C_CCMP_IMM;
  if (eq(0x5fe00000, 0x1ac00000)) return C_DP2;
  if (eq(0x5fe00000, 0x5ac00000)) return C_DP1;
  if (eq(0x1f000000, 0x1b000000)) return C_DP3;
  if (eq(0xff801fe0, 0x1e001000)) return C_FMOV_IMM;
  if (eq(0xfffffc00, 0x1e260000)) return C_FMOV_WS;
  if (eq(0xfffffc00, 0x9e660000)) return C_FMOV_XD;
  if (eq(0xfffffc00, 0x1e270000)) return C_FMOV_SW;
  if (eq(0xfffffc00, 0x9e670000)) return C_FMOV_DX;
  if (eq(0xfffffc00, 0x1e604000)) return C_FMOV_DD;
  if (eq(0xfffffc00, 0x1e204000)) return C_FMOV_SS;
  if (eq(0xfffffc00, 0x1e60c000)) return C_FABS_D;
  if (eq(0xfffffc00, 0x1e20c000)) return C_FABS_S;
  if (eq(0xfffffc00, 0x1e614000)) return C_FNEG_D;
  if (eq(0xfffffc00, 0x1e214000)) return C_FNEG_S;
  if (eq(0xfffffc00, 0x1e61c000)) return C_FSQRT_D;
  if (eq(0xfffffc00, 0x1e21c000)) return C_FSQRT_S;
  if (eq(0xffe0fc00, 0x7ee0d400)) return C_FABD_D;
  if (eq(0xffe0fc00, 0x7e20d400)) return C_FABD_S;
  if (eq(0xffe0fc00, 0x1e600800)) return C_FMUL_D;
  if (eq(0xffe0fc00, 0x1e200800)) return C_FMUL_S;
  if (eq(0xffe0fc00, 0x1e602800)) return C_FADD_D;
  if (eq(0xffe0fc00, 0x1e202800)) return C_FADD_S;
  if (eq(0xffe0fc00, 0x1e603800)) return C_FSUB_D;
  if (eq(0xffe0fc00, 0x1e203800)) return C_FSUB_S;
  if (eq(0xffe0fc00, 0x1e601800)) return C_FDIV_D;
  if (eq(0xffe0fc00, 0x1e201800)) return C_FDIV_S;
  // 浮点三操作数（融合乘加）
  if (eq(0xffe08000, 0x1f400000)) return C_FMADD_D;
  if (eq(0xffe08000, 0x1f000000)) return C_FMADD_S;
  if (eq(0xffe08000, 0x1f408000)) return C_FMSUB_D;
  if (eq(0xffe08000, 0x1f008000)) return C_FMSUB_S;
  if (eq(0xffe08000, 0x1f600000)) return C_FNMADD_D;
  if (eq(0xffe08000, 0x1f200000)) return C_FNMADD_S;
  if (eq(0xffe08000, 0x1f608000)) return C_FNMSUB_D;
  if (eq(0xffe08000, 0x1f208000)) return C_FNMSUB_S;
  // 注意顺序：#0.0 形式必须先判，否则会被寄存器形式的掩码吃掉
  // bits 4:0 区分 fcmp(00000)/fcmpe(10000) 与 #0.0 形式(01000/11000)，掩码必须含 bits 4:0
  if (eq(0xffe0fc1f, 0x1e602008)) return C_FCMP_D0;
  if (eq(0xffe0fc1f, 0x1e202008)) return C_FCMP_S0;
  if (eq(0xffe0fc1f, 0x1e602018)) return C_FCMP_D0;
  if (eq(0xffe0fc1f, 0x1e202018)) return C_FCMP_S0;
  if (eq(0xffe0fc1f, 0x1e602000)) return C_FCMP_D;
  if (eq(0xffe0fc1f, 0x1e602010)) return C_FCMP_D;
  if (eq(0xffe0fc1f, 0x1e202000)) return C_FCMP_S;
  if (eq(0xffe0fc1f, 0x1e202010)) return C_FCMP_S;
  if (eq(0xffe00c00, 0x1e600c00)) return C_FCSEL_D;
  if (eq(0xffe00c00, 0x1e200c00)) return C_FCSEL_S;
  if (eq(0xffe00c00, 0x1e600400)) return C_FCCMP_D;
  if (eq(0xffe00c00, 0x1e200400)) return C_FCCMP_S;
  if (eq(0xfffffc00, 0x1e780000)) return C_FCVTZS_WD;
  if (eq(0xfffffc00, 0x9e780000)) return C_FCVTZS_XD;
  if (eq(0xfffffc00, 0x1e790000)) return C_FCVTZU_WD;
  if (eq(0xfffffc00, 0x9e790000)) return C_FCVTZU_XD;
  if (eq(0xfffffc00, 0x1e290000)) return C_FCVTPU_WS;
  if (eq(0xfffffc00, 0x1e690000)) return C_FCVTPU_WD;
  if (eq(0xfffffc00, 0x9e290000)) return C_FCVTPU_XS;
  if (eq(0xfffffc00, 0x9e690000)) return C_FCVTPU_XD;
  if (eq(0xfffffc00, 0x1e620000)) return C_SCVTF_DW;
  if (eq(0xfffffc00, 0x9e620000)) return C_SCVTF_DX;
  if (eq(0xfffffc00, 0x1e630000)) return C_UCVTF_DW;
  if (eq(0xfffffc00, 0x9e630000)) return C_UCVTF_DX;
  if (eq(0xfffffc00, 0x5e61d800)) return C_SCVTF_DD;
  if (eq(0xfffffc00, 0x7e61d800)) return C_UCVTF_DD;
  if (eq(0xfffffc00, 0x5e21d800)) return C_SCVTF_SS;
  if (eq(0xfffffc00, 0x7e21d800)) return C_UCVTF_SS;
  if (eq(0xfffffc00, 0x1e220000)) return C_SCVTF_SW;
  if (eq(0xfffffc00, 0x1e230000)) return C_UCVTF_SW;
  if (eq(0xfffffc00, 0x9e220000)) return C_SCVTF_SX;
  if (eq(0xfffffc00, 0x9e230000)) return C_UCVTF_SX;
  if (eq(0xbf20fc00, 0x0e201c00)) return C_VEC_LOGIC;
  if (eq(0xbf20fc00, 0x0e208400)) return C_VEC_ADD;
  if (eq(0xbf20fc00, 0x2e208400)) return C_VEC_SUB;
  if (eq(0xbfe0fc00, 0x0e003c00)) return C_VEC_UMOV;
  if (eq(0xbfe0fc00, 0x0e000c00)) return C_VEC_DUP_GEN;
  if (eq(0xbfe0fc00, 0x0e000400)) return C_VEC_DUP_EL;
  // AdvSIMD modified immediate（MOVI 的各 cmode；op 位被掩掉，故两种 op 都命中）
  if (eq(0x9ff8fc00, 0x0f00e400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f000400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f002400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f004400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f006400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f008400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f00a400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f00c400)) return C_VEC_MOVI;
  if (eq(0x9ff8fc00, 0x0f00d400)) return C_VEC_MOVI;
  if (eq(0xbfe0fc00, 0x0e803800)) return C_VEC_ZIP1;
  if (eq(0xbfe0fc00, 0x0e801800)) return C_VEC_UZP1;
  if (eq(0xbfe08400, 0x2e000000)) return C_VEC_EXT;
  if (eq(0xbf20fc00, 0x2e204400)) return C_VEC_USHL;
  if (eq(0xbf80fc00, 0x0f00a400)) return C_VEC_SSHLL;
  // CNT：逐字节统计 1 的个数（popcount 的 NEON 实现常用）
  if (eq(0xbfe0fc00, 0x0e205800)) return C_VEC_CNT;
  // SADDLV/UADDLV：把各 lane 累加到双倍宽度的标量（bit29 = 有无符号）
  if (eq(0x1f3ffc00, 0x0e303800)) return C_VEC_UADDLV;
  // SHL（标量，立即数）：bits 31:24 = 0x5f，opcode = 0b01010
  if (eq(0xff00fc00, 0x5f005400)) return C_VEC_SHL_SC;
  // SHL（向量，立即数）：bits 18:16 = 0b010，bits 15:10 = 0b010101
  if (eq(0xbf07fc00, 0x0f045400)) return C_VEC_SHL_V;
  return C_UNKNOWN;
}

export type SvcHandler = (cpu: Cpu, imm: number) => void;
/** 返回 true 表示已处理（并已写好目标寄存器） */
export type SysRegHandler = (cpu: Cpu, isRead: boolean, key: number, rt: number) => boolean;

const PAGE_ALIGN = 0xfff;

export class Cpu {
  /** x0..x30，index 31 = sp；按 lo/hi 两个 32 位字存（JIT 热路径用） */
  readonly xlo = new Int32Array(32);
  readonly xhi = new Int32Array(32);
  /** 向量寄存器 v0..v31：每寄存器 128 位 = 4 个 int32 / 2 个 double */
  readonly vbuf = new ArrayBuffer(64 * 8);
  readonly vi = new Int32Array(this.vbuf);
  readonly vf = new Float64Array(this.vbuf);
  /** 兼容视图：x[i] / v[i] 按 BigInt 读写（仅调试与解释器慢路径使用） */
  readonly x: BigUint64Array = this.makeXView();
  readonly v: BigUint64Array = this.makeVView();
  nzcv = 0;
  pc = 0;
  tick = 0x100000;
  /** 已执行指令数（JIT 驱动用） */
  steps = 0;

  /** 独占监视器：LDXR/LDAXR 置位，STXR/STLXR 校验并清除 */
  private monAddr = -1;
  private monSize = 0;

  mem: ArmMem;
  svc?: SvcHandler;
  sysReg?: SysRegHandler;

  /** 由宿主维护的系统寄存器 */
  tpidr = 0n;
  cntvct: () => bigint = () => 0n;

  /** 指令字 → 分类 的直接映射缓存（避免 Map 哈希） */
  private readonly clsWord = new Int32Array(1 << 15);
  private readonly clsKind = new Uint8Array(1 << 15);
  /** 指令分类直方图（性能分析用；histOn=false 时只有一次布尔判断） */
  histOn = false;
  readonly hist = new Int32Array(128);
  /** 调试：强制指定指令类走慢路径（SO_SLOW=all 或类 id 逗号列表） */
  private readonly slowCls = new Uint8Array(128);
  /** 调试：SO_VERIFY=1 时逐条比对快慢路径 */
  private readonly verifyOn = process.env.SO_VERIFY === '1';
  /** 快路径已实现的指令类（调试对拍用） */
  private static readonly fastHas = (() => {
    const a = new Uint8Array(128);
    const ids = [
      C_MOVEWIDE, C_LOGIC_SHIFT, C_LDST_UOFF, C_BITFIELD, C_ADDSUB_SHIFT, C_LOGIC_IMM,
      C_LDST_UNSCALED, C_LDST_ROFF, C_ADDSUB_IMM, C_ADR, C_BR, C_LDST_PRE, C_BCOND,
      C_ADDSUB_EXT, C_VEC_LOGIC, C_VEC_UMOV, C_BBL, C_CSEL, C_PAIR, C_FMOV_WS,
      C_VEC_DUP_GEN, C_VEC_DUP_EL, C_CBZ, C_TBZ, C_RET, C_BLR, C_LDST_POST,
      C_LDST_LIT, C_EXTR, C_CCMP, C_CCMP_IMM, C_LDAR, C_STLR, C_CLREX, C_PAC,
      C_XPACLRI, C_BTI, C_HINT, C_BARRIER,
    ];
    for (const c of ids) a[c] = 1;
    return a;
  })();
  private readonly fpBuf = new ArrayBuffer(8);
  private readonly fpView = new DataView(this.fpBuf);

  constructor(mem: ArmMem) {
    this.mem = mem;
    const s = process.env.SO_SLOW;
    if (s) {
      if (s === 'all') this.slowCls.fill(1);
      else for (const x of s.split(',')) this.slowCls[Number(x)] = 1;
    }
  }

  /**
   * x 的 BigInt 兼容视图：真实存储是 xlo/xhi 两个 32 位字，
   * 这里用 Proxy 提供 cpu.x[i] 的 BigInt 读写，供宿主代码与解释器慢路径使用。
   */
  private makeXView(): BigUint64Array {
    const xlo = this.xlo;
    const xhi = this.xhi;
    return new Proxy(new BigUint64Array(32), {
      get(t, p) {
        if (typeof p === 'string') {
          const i = +p;
          if (i >= 0 && i < 32 && (i | 0) === i) {
            return (BigInt(xhi[i] >>> 0) << 32n) | BigInt(xlo[i] >>> 0);
          }
        }
        return Reflect.get(t, p) as unknown;
      },
      set(t, p, v) {
        if (typeof p === 'string') {
          const i = +p;
          if (i >= 0 && i < 32 && (i | 0) === i) {
            const b = BigInt.asUintN(64, BigInt(v as bigint));
            xlo[i] = Number(b & 0xffffffffn);
            xhi[i] = Number(b >> 32n);
            return true;
          }
        }
        return Reflect.set(t, p, v);
      },
    }) as BigUint64Array;
  }

  /** v 的 BigInt 兼容视图：v[2i] = 低 64 位，v[2i+1] = 高 64 位 */
  private makeVView(): BigUint64Array {
    const vi = this.vi;
    return new Proxy(new BigUint64Array(64), {
      get(t, p) {
        if (typeof p === 'string') {
          const j = +p;
          if (j >= 0 && j < 64 && (j | 0) === j) {
            const k = j * 2;
            return (BigInt(vi[k + 1] >>> 0) << 32n) | BigInt(vi[k] >>> 0);
          }
        }
        return Reflect.get(t, p) as unknown;
      },
      set(t, p, v) {
        if (typeof p === 'string') {
          const j = +p;
          if (j >= 0 && j < 64 && (j | 0) === j) {
            const b = BigInt.asUintN(64, BigInt(v as bigint));
            const k = j * 2;
            vi[k] = Number(b & 0xffffffffn);
            vi[k + 1] = Number(b >> 32n);
            return true;
          }
        }
        return Reflect.set(t, p, v);
      },
    }) as BigUint64Array;
  }

  /** 快照 / 恢复全部现场（嵌套调用 so 函数用，频率极低） */
  saveRegs(): { x: bigint[]; v: bigint[] } {
    const x: bigint[] = new Array(32);
    const v: bigint[] = new Array(64);
    for (let i = 0; i < 32; i++) x[i] = this.x[i];
    for (let i = 0; i < 64; i++) v[i] = this.v[i];
    return { x, v };
  }

  restoreRegs(s: { x: bigint[]; v: bigint[] }): void {
    for (let i = 0; i < 32; i++) this.x[i] = s.x[i];
    for (let i = 0; i < 64; i++) this.v[i] = s.v[i];
  }

  // ---------------------------------------------------------------- 寄存器
  /** 通用读：31 号读作 0 */
  rx(n: number): bigint {
    return n === 31 ? 0n : this.x[n];
  }
  /** 通用写：31 号丢弃 */
  wx(n: number, val: bigint): void {
    if (n !== 31) this.x[n] = val;
  }
  /** 含 sp：31 号就是 sp */
  rxn(n: number): bigint {
    return this.x[n];
  }
  wxn(n: number, val: bigint): void {
    this.x[n] = val;
  }
  /** 32 位视图 */
  rx32(n: number): bigint {
    return this.rx(n) & MASK32;
  }

  /** 向量寄存器低 64 位 */
  vlo(i: number): bigint {
    const k = i * 4;
    return (BigInt(this.vi[k + 1] >>> 0) << 32n) | BigInt(this.vi[k] >>> 0);
  }
  /** 向量寄存器高 64 位 */
  vhi(i: number): bigint {
    const k = i * 4 + 2;
    return (BigInt(this.vi[k + 1] >>> 0) << 32n) | BigInt(this.vi[k] >>> 0);
  }
  setVlo(i: number, val: bigint): void {
    const k = i * 4;
    this.vi[k] = Number(val & 0xffffffffn);
    this.vi[k + 1] = Number((val >> 32n) & 0xffffffffn);
  }
  setVhi(i: number, val: bigint): void {
    const k = i * 4 + 2;
    this.vi[k] = Number(val & 0xffffffffn);
    this.vi[k + 1] = Number((val >> 32n) & 0xffffffffn);
  }

  // ---------------------------------------------------------------- 标志
  /** 只算 N/Z，C/V 由调用方给 */
  private nz(result: bigint, sf: number): number {
    const M = sf ? MASK64 : MASK32;
    const r = result & M;
    const sign = sf ? r >> 63n : r >> 31n;
    return (sign ? F_N : 0) | (r === 0n ? F_Z : 0);
  }

  addsub(a: bigint, b: bigint, sub: boolean, sf: number, setF: boolean): bigint {
    const M = sf ? MASK64 : MASK32;
    const signBit = sf ? 1n << 63n : 1n << 31n;
    const x = a & M;
    const y = b & M;
    if (sub) {
      const r = (x - y) & M;
      if (setF) {
        const c = x >= y ? F_C : 0;
        const v = ((x ^ y) & (x ^ r) & signBit) !== 0n ? F_V : 0;
        this.nzcv = this.nz(r, sf) | c | v;
      }
      return r;
    }
    const r = (x + y) & M;
    if (setF) {
      const c = r < x ? F_C : 0;
      const v = (~(x ^ y) & (x ^ r) & signBit) !== 0n ? F_V : 0;
      this.nzcv = this.nz(r, sf) | c | v;
    }
    return r;
  }

  cond(c: number): boolean {
    if (c >= 14) return true;
    const nzcv = this.nzcv;
    const n = (nzcv & F_N) !== 0;
    const z = (nzcv & F_Z) !== 0;
    const cy = (nzcv & F_C) !== 0;
    const v = (nzcv & F_V) !== 0;
    let r: boolean;
    switch (c >> 1) {
      case 0: r = z; break;
      case 1: r = cy; break;
      case 2: r = n; break;
      case 3: r = v; break;
      case 4: r = cy && !z; break;
      case 5: r = n === v; break;
      case 6: r = n === v && !z; break;
      default: r = true; break;
    }
    return (c & 1) !== 0 ? !r : r;
  }

  /** 移位寄存器操作数（LSL/LSR/ASR/ROR） */
  shiftReg(val: bigint, type: number, amount: number, sf: number): bigint {
    const w = sf ? 64 : 32;
    const M = sf ? MASK64 : MASK32;
    const v = val & M;
    const a = BigInt(amount & (w - 1));
    switch (type) {
      case 0: return (v << a) & M;
      case 1: return v >> a;
      case 2: return BigInt.asUintN(w, BigInt.asIntN(w, v) >> a);
      default: return a === 0n ? v : ((v >> a) | (v << BigInt(w) - a)) & M;
    }
  }

  /** 扩展寄存器操作数 */
  extendReg(val: bigint, opt: number, shift: number, sf: number): bigint {
    const M = sf ? MASK64 : MASK32;
    let r: bigint;
    switch (opt) {
      case 0: r = val & 0xffn; break;
      case 1: r = val & 0xffffn; break;
      case 2: r = val & MASK32; break;
      case 3: r = val & MASK64; break;
      case 4: r = BigInt.asUintN(64, BigInt.asIntN(8, val)); break;
      case 5: r = BigInt.asUintN(64, BigInt.asIntN(16, val)); break;
      case 6: r = BigInt.asUintN(64, BigInt.asIntN(32, val)); break;
      default: r = val & MASK64; break;
    }
    return (r << BigInt(shift)) & M;
  }

  // ---------------------------------------------------------------- 内存
  ld(addr: number, size: number): bigint {
    if ((addr & PAGE_ALIGN) !== ((addr + size - 1) & PAGE_ALIGN) && size > 1) {
      return this.mem.read(addr, size);
    }
    return this.mem.read(addr, size);
  }
  st(addr: number, size: number, val: bigint): void {
    this.mem.write(addr, size, val);
  }

  // ---------------------------------------------------------------- 单步
  step(): void {
    const w = this.mem.fetch(this.pc);
    const wi = w | 0;
    const slot = (wi ^ (wi >>> 15)) & 0x7fff;
    let c: number;
    if (this.clsWord[slot] === wi) {
      c = this.clsKind[slot] - 1;
    } else {
      c = classify(w);
      this.clsWord[slot] = wi;
      this.clsKind[slot] = c + 1;
    }
    if (this.histOn) this.hist[c] += 1;
    const next = this.pc + 4;
    this.pc = next;
    this.exec(c, w);
    this.steps += 1;
    if (this.tick-- <= 0) throw new Error(`指令预算耗尽 @0x${(this.pc - 4).toString(16)}`);
  }

  // ---------------------------------------------------------------- 立即数
  /**
   * 由 N:imms:immr 生成位掩码（逻辑立即数 / 位域用）。
   * 已验证：bitfield 的 425 条真实编码全部匹配。
   */
  decodeBitMasks(N: number, imms: number, immr: number, sf: number): bigint {
    const probe = (N << 6) | (~imms & 0x3f);
    const len = 31 - Math.clz32(probe);
    if (len < 1) throw new Error('非法位掩码');
    const esize = 1 << len;
    const levels = esize - 1;
    const S = imms & levels;
    const R = immr & levels;
    // ARM ARM：elem = ROR(Ones(S+1), R)，再按 esize 平铺
    const emask = (1n << BigInt(esize)) - 1n;
    const welem = (1n << BigInt(S + 1)) - 1n;
    const elem = R === 0
      ? welem
      : (((welem >> BigInt(R)) | (welem << BigInt(esize - R))) & emask);
    const dsz = sf ? 64 : 32;
    let out = 0n;
    for (let i = 0; i < dsz; i += esize) out |= elem << BigInt(i);
    return out & (sf ? MASK64 : MASK32);
  }

  /** 访存实际访问字节数（含 128 位 Q 形式） */
  private ldstBytes(w: number): number {
    const size = w >>> 30;
    const V = (w >>> 26) & 1;
    const opc = (w >>> 22) & 3;
    return V === 1 && size === 0 && opc >= 2 ? 16 : 1 << size;
  }

  /** 单个寄存器的 load/store（size/opc/V 语义见 ARM ARM LDST 编码） */
  private ldstOne(w: number, addr: number): void {
    const size = w >>> 30;
    const bytes = this.ldstBytes(w);
    const V = (w >>> 26) & 1;
    const opc = (w >>> 22) & 3;
    const rt = w & 31;
    if (V === 1) {
      // size=00 且 opc>=10 → 128 位 Q（opc=10 存、opc=11 取）
      if (size === 0 && opc >= 2) {
        if (opc === 2) {
          this.st(addr, 8, this.vlo(rt));
          this.st(addr + 8, 8, this.vhi(rt));
        } else {
          this.setVlo(rt, this.ld(addr, 8));
          this.setVhi(rt, this.ld(addr + 8, 8));
        }
        return;
      }
      if (opc === 0) {
        this.st(addr, bytes, this.vlo(rt));
      } else if (opc === 1) {
        this.setVlo(rt, this.ld(addr, bytes));
        this.setVhi(rt, 0n); // 写 B/H/S/D 均清零 127:esize
      }
      return;
    }
    if (opc === 0) {
      this.st(addr, bytes, this.rx(rt));
      return;
    }
    if (opc === 1) {
      this.wx(rt, this.ld(addr, bytes)); // LDR（32 位自然零扩展）
      return;
    }
    if (size === 3) return; // PRFM
    // opc=10 → LDRSW；opc=11 → LDRSB/LDRSH/LDRSW
    const sx = BigInt.asIntN(bytes * 8, this.ld(addr, bytes));
    this.wx(rt, size === 2 ? BigInt.asUintN(64, sx) : BigInt.asUintN(32, sx));
  }

  /** LDP/STP：idx 00=offset 01=post 10=offset 11=pre */
  private ldstPair(w: number, rn: number, imm: bigint, idx: number): void {
    const opc = w >>> 30;
    const L = (w >>> 22) & 1;
    const V = (w >>> 26) & 1;
    // 整数：opc 00=32 位，01=LDPSW(32→64 符号扩展)，10=64 位；SIMD：opc 00/01/10 → 32/64/128 位
    const bytes = V === 1 ? (4 << opc) : (opc === 2 ? 8 : 4);
    const rt = w & 31;
    const rt2 = (w >>> 10) & 31;
    const base = Number(this.rxn(rn));
    const addr = idx === 1 ? base : base + Number(imm);
    if (L === 1) {
      if (V === 1) {
        if (bytes === 16) {
          this.setVlo(rt, this.ld(addr, 8));
          this.setVhi(rt, this.ld(addr + 8, 8));
          this.setVlo(rt2, this.ld(addr + 16, 8));
          this.setVhi(rt2, this.ld(addr + 24, 8));
        } else {
          this.setVlo(rt, this.ld(addr, bytes));
          this.setVhi(rt, 0n);
          this.setVlo(rt2, this.ld(addr + bytes, bytes));
          this.setVhi(rt2, 0n);
        }
      } else if (opc === 2) {
        this.wx(rt, this.ld(addr, 8));
        this.wx(rt2, this.ld(addr + 8, 8));
      } else if (opc === 1) {
        // LDPSW：32 位符号扩展到 64 位
        this.wx(rt, BigInt.asUintN(64, BigInt.asIntN(32, this.ld(addr, 4))));
        this.wx(rt2, BigInt.asUintN(64, BigInt.asIntN(32, this.ld(addr + 4, 4))));
      } else {
        this.wx(rt, this.ld(addr, 4));
        this.wx(rt2, this.ld(addr + 4, 4));
      }
    } else if (V === 1) {
      if (bytes === 16) {
        this.st(addr, 8, this.vlo(rt));
        this.st(addr + 8, 8, this.vhi(rt));
        this.st(addr + 16, 8, this.vlo(rt2));
        this.st(addr + 24, 8, this.vhi(rt2));
      } else {
        this.st(addr, bytes, this.vlo(rt));
        this.st(addr + bytes, bytes, this.vlo(rt2));
      }
    } else {
      this.st(addr, bytes, this.rx(rt));
      this.st(addr + bytes, bytes, this.rx(rt2));
    }
    if (idx === 1) this.wxn(rn, BigInt(base + Number(imm)));
    else if (idx === 3) this.wxn(rn, BigInt(base + Number(imm)));
  }

  // ---------------------------------------------------------------- 浮点
  private getF64(i: number): number {
    this.fpView.setBigUint64(0, this.vlo(i));
    return this.fpView.getFloat64(0);
  }
  private setF64(i: number, v: number): void {
    this.fpView.setFloat64(0, v);
    this.setVlo(i, this.fpView.getBigUint64(0));
    this.setVhi(i, 0n); // 写 D 寄存器会清零 Q 的高 64 位（与 unicorn/ARM 一致）
  }
  private getF32(i: number): number {
    this.fpView.setUint32(0, Number(this.vlo(i) & MASK32));
    return this.fpView.getFloat32(0);
  }
  private setF32(i: number, v: number): void {
    this.fpView.setFloat32(0, v);
    this.setVlo(i, BigInt(this.fpView.getUint32(0)));
    this.setVhi(i, 0n); // 写 S 寄存器会清零 127:32
  }
  /** FCMP 风格的标志设置 */
  private fpCompare(a: number, b: number): void {
    if (Number.isNaN(a) || Number.isNaN(b)) {
      this.nzcv = F_C | F_V;
    } else if (a < b) {
      this.nzcv = F_N;
    } else if (a === b) {
      this.nzcv = F_Z | F_C;
    } else {
      this.nzcv = F_C;
    }
  }
  /** VFPExpandImm：8 位立即数 → 浮点位模式（ARM ARM 定义） */
  private vfpExpand(imm8: number, single: boolean): bigint {
    const sign = (imm8 >> 7) & 1;
    const b6 = (imm8 >> 6) & 1;
    const low6 = imm8 & 0x3f;
    const frac = BigInt(low6 & 0xf); // imm8[3:0] 进入小数最高 4 位
    if (single) {
      // sign:NOT(b6):Replicate(b6,5):imm8[5:0]:Zeros(19)
      const exp = ((b6 ^ 1) << 7) | (b6 ? 0x1f : 0) << 2 | ((low6 >> 4) & 3);
      return BigInt(((sign << 31) | (exp << 23)) >>> 0) | (frac << 19n);
    }
    // sign:NOT(b6):Replicate(b6,8):imm8[5:0]:Zeros(48)
    const exp = ((b6 ^ 1) << 10) | (b6 ? 0xff : 0) << 2 | ((low6 >> 4) & 3);
    return (BigInt(sign) << 63n) | (BigInt(exp) << 52n) | (frac << 48n);
  }

  // ---------------------------------------------------------------- SIMD
  /** 取向量寄存器第 index 个 esize 位元素（esize ∈ {8,16,32,64}） */
  private getLane(reg: number, index: number, esize: number): bigint {
    const bit = index * esize;
    const mask = (1n << BigInt(esize)) - 1n;
    return bit < 64
      ? (this.vlo(reg) >> BigInt(bit)) & mask
      : (this.vhi(reg) >> BigInt(bit - 64)) & mask;
  }
  private setLane(reg: number, index: number, esize: number, val: bigint): void {
    const bit = index * esize;
    const mask = (1n << BigInt(esize)) - 1n;
    const x = val & mask;
    if (bit < 64) {
      this.setVlo(reg, (this.vlo(reg) & ~(mask << BigInt(bit))) | (x << BigInt(bit)));
    } else {
      const s = bit - 64;
      this.setVhi(reg, (this.vhi(reg) & ~(mask << BigInt(s))) | (x << BigInt(s)));
    }
  }
  /** 由 imm5 求元素位宽与 lane 下标 */
  private imm5ToLane(imm5: number): { esize: number; index: number } {
    const low = imm5 & -imm5;
    const size = 31 - Math.clz32(low);
    return { esize: 8 << size, index: imm5 >> (size + 1) };
  }

  // ================================================================ 数值快路径
  // 热门指令类改成纯 number（lo/hi 各 32 位）运算：不碰 cpu.x / cpu.v 的 Proxy，
  // 也不构造 BigInt。语义与 execSlow 里的 BigInt 实现逐条对齐。
  private rlo = 0;
  private rhi = 0;
  private bmLo = 0;
  private bmHi = 0;
  private readonly t1 = new Int32Array(1);

  /** x[n] → rlo/rhi（n=31 读作 0） */
  private gx(n: number): void {
    if (n === 31) {
      this.rlo = 0;
      this.rhi = 0;
    } else {
      this.rlo = this.xlo[n];
      this.rhi = this.xhi[n];
    }
  }

  /** 含 sp 读 x[n] → rlo/rhi */
  private gxs(n: number): void {
    this.rlo = this.xlo[n];
    this.rhi = this.xhi[n];
  }

  /** rlo/rhi → x[rd]（rd=31 丢弃） */
  private sx(rd: number): void {
    if (rd !== 31) {
      this.xlo[rd] = this.rlo;
      this.xhi[rd] = this.rhi;
    }
  }

  /** rlo/rhi → x[rd]（含 sp） */
  private sxs(rd: number): void {
    this.xlo[rd] = this.rlo;
    this.xhi[rd] = this.rhi;
  }

  /** 写 32 位结果（零扩展到 64；rd=31 丢弃） */
  private sx32(rd: number, v: number): void {
    if (rd !== 31) {
      this.xlo[rd] = v;
      this.xhi[rd] = 0;
    }
  }

  /** 把 number（|v| < 2^53）写成 64 位寄存器值（rd=31 丢弃） */
  private sxNum(rd: number, v: number): void {
    if (rd === 31) return;
    this.xlo[rd] = v | 0;
    this.xhi[rd] = Math.floor(v / 4294967296) | 0;
  }

  /** 含 sp 版 */
  private sxNumS(rd: number, v: number): void {
    this.xlo[rd] = v | 0;
    this.xhi[rd] = Math.floor(v / 4294967296) | 0;
  }

  /** 读 64 位寄存器为 number（含 sp） */
  private num(n: number): number {
    return (this.xhi[n] >>> 0) * 4294967296 + (this.xlo[n] >>> 0);
  }

  /** rlo/rhi = a ± b；b 由参数给出，a 在 rlo/rhi。sf=0 时只保留低 32 位。 */
  private addsubN(bLo: number, bHi: number, sub: boolean, sf: number, setF: boolean): void {
    const aLo = this.rlo;
    const aHi = this.rhi;
    let lo: number;
    let hi: number;
    if (sf === 1) {
      if (sub) {
        const d = (aLo >>> 0) - (bLo >>> 0);
        const hd = (aHi >>> 0) - (bHi >>> 0) - (d < 0 ? 1 : 0);
        lo = d | 0;
        hi = hd | 0;
        if (setF) {
          const v = (((aHi ^ bHi) & (aHi ^ hi)) >>> 31) & 1;
          this.nzcv = ((hi >>> 31) << 3) | (((lo | hi) === 0 ? 1 : 0) << 2) | (hd < 0 ? 0 : F_C) | (v ? F_V : 0);
        }
      } else {
        const s = (aLo >>> 0) + (bLo >>> 0);
        const hs = (aHi >>> 0) + (bHi >>> 0) + (s > 0xffffffff ? 1 : 0);
        lo = s | 0;
        hi = hs | 0;
        if (setF) {
          const v = ((~(aHi ^ bHi) & (aHi ^ hi)) >>> 31) & 1;
          this.nzcv = ((hi >>> 31) << 3) | (((lo | hi) === 0 ? 1 : 0) << 2) | (hs > 0xffffffff ? F_C : 0) | (v ? F_V : 0);
        }
      }
    } else if (sub) {
      const d = (aLo >>> 0) - (bLo >>> 0);
      lo = d | 0;
      if (setF) {
        const v = (((aLo ^ bLo) & (aLo ^ lo)) >>> 31) & 1;
        this.nzcv = ((lo >>> 31) << 3) | ((lo === 0 ? 1 : 0) << 2) | (d < 0 ? 0 : F_C) | (v ? F_V : 0);
      }
      hi = 0;
    } else {
      const s = (aLo >>> 0) + (bLo >>> 0);
      lo = s | 0;
      if (setF) {
        const v = ((~(aLo ^ bLo) & (aLo ^ lo)) >>> 31) & 1;
        this.nzcv = ((lo >>> 31) << 3) | ((lo === 0 ? 1 : 0) << 2) | (s > 0xffffffff ? F_C : 0) | (v ? F_V : 0);
      }
      hi = 0;
    }
    this.rlo = lo;
    this.rhi = hi;
  }

  /** rlo/rhi = rlo/rhi 逻辑/算术移位（type 0 LSL 1 LSR 2 ASR 3 ROR） */
  private shiftN(type: number, amount: number, sf: number): void {
    const alo = this.rlo;
    const ahi = this.rhi;
    if (sf === 1) {
      const n = amount & 63;
      if (type === 0) {
        if (n === 0) { this.rlo = alo; this.rhi = ahi; }
        else if (n < 32) { this.rlo = alo << n; this.rhi = (ahi << n) | (alo >>> (32 - n)); }
        else if (n === 32) { this.rlo = 0; this.rhi = alo; }
        else { this.rlo = 0; this.rhi = alo << (n - 32); }
      } else if (type === 1) {
        if (n === 0) { this.rlo = alo; this.rhi = ahi; }
        else if (n < 32) { this.rlo = (alo >>> n) | (ahi << (32 - n)); this.rhi = ahi >>> n; }
        else if (n === 32) { this.rlo = ahi; this.rhi = 0; }
        else { this.rlo = ahi >>> (n - 32); this.rhi = 0; }
      } else if (type === 2) {
        if (n === 0) { this.rlo = alo; this.rhi = ahi; }
        else if (n < 32) { this.rlo = (alo >>> n) | (ahi << (32 - n)); this.rhi = ahi >> n; }
        else if (n === 32) { this.rlo = ahi; this.rhi = ahi >> 31; }
        else { this.rlo = ahi >> (n - 32); this.rhi = ahi >> 31; }
      } else if (n === 0) {
        this.rlo = alo;
        this.rhi = ahi;
      } else if (n < 32) {
        this.rlo = (alo >>> n) | (ahi << (32 - n));
        this.rhi = (ahi >>> n) | (alo << (32 - n));
      } else if (n === 32) {
        this.rlo = ahi;
        this.rhi = alo;
      } else {
        const m = n - 32;
        this.rlo = (ahi >>> m) | (alo << (32 - m));
        this.rhi = (alo >>> m) | (ahi << (32 - m));
      }
      return;
    }
    const n = amount & 31;
    if (type === 0) { this.rlo = alo << n; this.rhi = 0; }
    else if (type === 1) { this.rlo = alo >>> n; this.rhi = 0; }
    else if (type === 2) { this.rlo = alo >> n; this.rhi = 0; }
    else { this.rlo = n === 0 ? alo : ((alo >>> n) | (alo << (32 - n))); this.rhi = 0; }
  }

  /** rlo/rhi = 扩展（option 0 UXTB … 7 SXTX）后左移 shift 位 */
  private extendN(opt: number, shift: number, sf: number): void {
    const alo = this.rlo;
    const ahi = this.rhi;
    let lo: number;
    let hi: number;
    switch (opt) {
      case 0: lo = alo & 0xff; hi = 0; break;
      case 1: lo = alo & 0xffff; hi = 0; break;
      case 2: lo = alo; hi = 0; break;
      case 3: lo = alo; hi = ahi; break;
      case 4: lo = (alo << 24) >> 24; hi = lo >> 31; break;
      case 5: lo = (alo << 16) >> 16; hi = lo >> 31; break;
      case 6: lo = alo; hi = alo >> 31; break;
      default: lo = alo; hi = ahi; break;
    }
    if (sf === 1) {
      const n = shift & 63;
      if (n === 0) { this.rlo = lo; this.rhi = hi; }
      else if (n < 32) { this.rlo = lo << n; this.rhi = (hi << n) | (lo >>> (32 - n)); }
      else { this.rlo = 0; this.rhi = lo << (n - 32); }
    } else {
      this.rlo = lo << (shift & 31);
      this.rhi = 0;
    }
  }

  /** 从 64 位值里取 [offset, offset+width) 位到 rlo/rhi */
  private extractN(slo: number, shi: number, offset: number, width: number): void {
    if (offset === 0) { this.rlo = slo; this.rhi = shi; }
    else if (offset < 32) {
      this.rlo = (slo >>> offset) | (shi << (32 - offset));
      this.rhi = shi >>> offset;
    } else if (offset === 32) { this.rlo = shi; this.rhi = 0; }
    else { this.rlo = shi >>> (offset - 32); this.rhi = 0; }
    if (width < 32) { this.rlo &= (1 << width) - 1; this.rhi = 0; }
    else if (width === 32) { this.rhi = 0; }
    else if (width < 64) { this.rhi &= (1 << (width - 32)) - 1; }
  }

  /** 逻辑立即数掩码 → bmLo/bmHi（对应 decodeBitMasks 的 number 版） */
  private decodeBitMasksNum(N: number, imms: number, immr: number, sf: number): void {
    const probe = (N << 6) | (~imms & 0x3f);
    const len = 31 - Math.clz32(probe);
    if (len < 1) throw new Error('非法位掩码');
    const esize = 1 << len;
    const levels = esize - 1;
    const S = imms & levels;
    const R = immr & levels;
    if (esize === 64) {
      let wlo: number;
      let whi: number;
      if (S === 63) { wlo = -1; whi = -1; }
      else if (S < 31) { wlo = (1 << (S + 1)) - 1; whi = 0; }
      else if (S === 31) { wlo = -1; whi = 0; }
      else { wlo = -1; whi = (1 << (S - 31)) - 1; }
      if (R === 0) { this.bmLo = wlo; this.bmHi = whi; }
      else if (R < 32) {
        this.bmLo = (wlo >>> R) | (whi << (32 - R));
        this.bmHi = (whi >>> R) | (wlo << (32 - R));
      } else if (R === 32) { this.bmLo = whi; this.bmHi = wlo; }
      else {
        const m = R - 32;
        this.bmLo = (whi >>> m) | (wlo << (32 - m));
        this.bmHi = (wlo >>> m) | (whi << (32 - m));
      }
      return;
    }
    const emask = esize === 32 ? -1 : (1 << esize) - 1;
    const welem = S + 1 >= 32 ? -1 : (1 << (S + 1)) - 1;
    const elem = R === 0 ? welem : ((welem >>> R) | (welem << (esize - R))) & emask;
    let rep: number;
    if (esize === 32) rep = elem;
    else if (esize === 16) rep = (elem | (elem << 16)) | 0;
    else if (esize === 8) rep = (elem * 0x01010101) | 0;
    else {
      rep = 0;
      for (let b = 0; b < 32; b += esize) rep |= elem << b;
    }
    this.bmLo = rep;
    this.bmHi = sf === 1 ? rep : 0;
  }

  /** 取向量通道（esize=64 时 lo/hi 都有值）→ rlo/rhi */
  private laneN(reg: number, index: number, esize: number): void {
    const vi = this.vi;
    const bit = index * esize;
    const k = reg * 4 + (bit >>> 5);
    if (esize === 64) {
      this.rlo = vi[k];
      this.rhi = vi[k + 1];
      return;
    }
    const sh = bit & 31;
    const v = (vi[k] >>> sh) | (sh === 0 ? 0 : vi[k + 1] << (32 - sh));
    this.rhi = 0;
    if (esize === 32) this.rlo = v | 0;
    else if (esize === 16) this.rlo = v & 0xffff;
    else this.rlo = v & 0xff;
  }

  // ---- 向量 lane 级 number 实现（JIT 直接调用，避免 BigInt 与 dispatch） ----

  /** 读一个 lane（esize=64 时只返回低 32 位，高 32 位需读 vi[k+1]） */
  private laneOf(reg: number, i: number, esize: number): number {
    const bit = i * esize;
    const k = reg * 4 + (bit >>> 5);
    const vi = this.vi;
    if (esize === 64) return vi[k];
    const sh = bit & 31;
    const v = (vi[k] >>> sh) | (sh === 0 ? 0 : vi[k + 1] << (32 - sh));
    return esize === 32 ? v | 0 : v & ((1 << esize) - 1);
  }

  /** 写一个 lane（esize=64 时写 lo/hi） */
  private setLaneOf(reg: number, i: number, esize: number, lo: number, hi = 0): void {
    const bit = i * esize;
    const k = reg * 4 + (bit >>> 5);
    const vi = this.vi;
    if (esize === 64) {
      vi[k] = lo | 0;
      vi[k + 1] = hi | 0;
      return;
    }
    if (esize === 32) {
      vi[k] = lo | 0;
      return;
    }
    const sh = bit & 31;
    const full = esize === 16 ? 0xffff : 0xff;
    const mask = full << sh;
    vi[k] = (vi[k] & ~mask) | ((lo << sh) & mask);
    if (sh + esize > 32) {
      const sh2 = 32 - sh;
      const mask2 = full >>> sh2;
      vi[k + 1] = (vi[k + 1] & ~mask2) | ((lo >>> sh2) & mask2);
    }
  }

  /** ZIP1 / UZP1 */
  vzipN(w: number, zip: boolean): void {
    const Q = (w >>> 30) & 1;
    const esize = 8 << ((w >>> 22) & 3);
    const rm = (w >>> 16) & 31;
    const rn = (w >>> 5) & 31;
    const rd = w & 31;
    const lanes = (Q === 1 ? 128 : 64) / esize;
    const half = lanes >> 1;
    const as: number[] = [];
    const bs: number[] = [];
    const ah: number[] = [];
    const bh: number[] = [];
    for (let i = 0; i < lanes; i++) {
      as.push(this.laneOf(rn, i, esize));
      bs.push(this.laneOf(rm, i, esize));
      if (esize === 64) {
        ah.push(this.vi[rn * 4 + i * 2 + 1]);
        bh.push(this.vi[rm * 4 + i * 2 + 1]);
      }
    }
    for (let i = 0; i < half; i++) {
      if (zip) {
        this.setLaneOf(rd, 2 * i, esize, as[i], ah[i] ?? 0);
        this.setLaneOf(rd, 2 * i + 1, esize, bs[i], bh[i] ?? 0);
      } else {
        this.setLaneOf(rd, i, esize, as[2 * i], ah[2 * i] ?? 0);
        this.setLaneOf(rd, half + i, esize, bs[2 * i], bh[2 * i] ?? 0);
      }
    }
    if (Q === 0) {
      this.vi[rd * 4 + 2] = 0;
      this.vi[rd * 4 + 3] = 0;
    }
  }

  /** EXT：按字节把 rn||rm 右移 imm4 字节 */
  vextN(w: number): void {
    const Q = (w >>> 30) & 1;
    const imm4 = (w >>> 11) & 0xf;
    const rm = (w >>> 16) & 31;
    const rn = (w >>> 5) & 31;
    const rd = w & 31;
    const vi = this.vi;
    const W = [
      vi[rn * 4], vi[rn * 4 + 1], vi[rn * 4 + 2], vi[rn * 4 + 3],
      vi[rm * 4], vi[rm * 4 + 1], vi[rm * 4 + 2], vi[rm * 4 + 3],
    ];
    const sw = imm4 >>> 2;
    const sh = (imm4 & 3) * 8;
    const r0 = sh === 0 ? W[sw] : (W[sw] >>> sh) | (W[sw + 1] << (32 - sh));
    const r1 = sh === 0 ? W[sw + 1] : (W[sw + 1] >>> sh) | (W[sw + 2] << (32 - sh));
    const r2 = sh === 0 ? W[sw + 2] : (W[sw + 2] >>> sh) | (W[sw + 3] << (32 - sh));
    const r3 = sh === 0 ? W[sw + 3] : (W[sw + 3] >>> sh) | (W[sw + 4] << (32 - sh));
    vi[rd * 4] = r0;
    vi[rd * 4 + 1] = r1;
    vi[rd * 4 + 2] = Q === 1 ? r2 : 0;
    vi[rd * 4 + 3] = Q === 1 ? r3 : 0;
  }

  /** USHL（无符号右移形式） */
  vushlN(w: number): void {
    const Q = (w >>> 30) & 1;
    const esize = 8 << ((w >>> 22) & 3);
    const rm = (w >>> 16) & 31;
    const rn = (w >>> 5) & 31;
    const rd = w & 31;
    const lanes = (Q === 1 ? 128 : 64) / esize;
    const mask = esize === 32 ? -1 : (1 << esize) - 1;
    const as: number[] = [];
    const bs: number[] = [];
    const ah: number[] = [];
    const bh: number[] = [];
    for (let i = 0; i < lanes; i++) {
      as.push(this.laneOf(rn, i, esize));
      bs.push(this.laneOf(rm, i, esize));
      if (esize === 64) {
        ah.push(this.vi[rn * 4 + i * 2 + 1]);
        bh.push(this.vi[rm * 4 + i * 2 + 1]);
      }
    }
    for (let i = 0; i < lanes; i++) {
      if (esize === 64) {
        const a = (BigInt(ah[i] >>> 0) << 32n) | BigInt(as[i] >>> 0);
        const sh = BigInt.asIntN(64, (BigInt(bh[i] >>> 0) << 32n) | BigInt(bs[i] >>> 0));
        let r: bigint;
        if (sh >= 64n || sh <= -64n) r = 0n;
        else if (sh >= 0n) r = (a << sh) & MASK64;
        else r = a >> -sh;
        this.setLaneOf(rd, i, 64, Number(r & 0xffffffffn) | 0, Number(r >> 32n) | 0);
        continue;
      }
      const sh = (bs[i] << (32 - esize)) >> (32 - esize);
      let r: number;
      if (sh >= esize || sh <= -esize) r = 0;
      else if (sh >= 0) r = (as[i] << sh) & mask;
      else r = (as[i] >>> -sh) & mask;
      this.setLaneOf(rd, i, esize, r);
    }
    if (Q === 0) {
      this.vi[rd * 4 + 2] = 0;
      this.vi[rd * 4 + 3] = 0;
    }
  }

  /** DUP（element / general），镜像 execFast 的两条快路径 */
  vdupN(w: number, el: boolean): void {
    const Q = (w >>> 30) & 1;
    const lane = this.imm5ToLane((w >>> 16) & 0x1f);
    const esize = lane.esize;
    if (el) this.laneN((w >>> 5) & 31, lane.index, esize);
    else this.gx((w >>> 5) & 31);
    let lo = this.rlo;
    let hi = this.rhi;
    if (esize !== 64) {
      const v = lo & (esize === 32 ? -1 : (1 << esize) - 1);
      if (esize === 32) {
        lo = v;
        hi = v;
      } else if (esize === 16) {
        lo = (v | (v << 16)) | 0;
        hi = lo;
      } else {
        lo = (v * 0x01010101) | 0;
        hi = lo;
      }
    }
    const k = (w & 31) * 4;
    const vi = this.vi;
    vi[k] = lo;
    vi[k + 1] = hi;
    vi[k + 2] = Q === 1 ? lo : 0;
    vi[k + 3] = Q === 1 ? hi : 0;
  }

  /** 单寄存器访存（number 版） */
  private ldstOneN(w: number, addr: number): void {
    const size = w >>> 30;
    const V = (w >>> 26) & 1;
    const opc = (w >>> 22) & 3;
    const rt = w & 31;
    const mem = this.mem;
    const vi = this.vi;
    if (V === 1) {
      const k = rt * 4;
      if (size === 0 && opc >= 2) {
        if (opc === 2) {
          mem.st64(addr, vi[k], vi[k + 1]);
          mem.st64(addr + 8, vi[k + 2], vi[k + 3]);
        } else {
          vi[k] = mem.ld64(addr, this.t1);
          vi[k + 1] = this.t1[0];
          vi[k + 2] = mem.ld64(addr + 8, this.t1);
          vi[k + 3] = this.t1[0];
        }
        return;
      }
      const bytes = 1 << size;
      if (opc === 0) {
        if (bytes === 8) mem.st64(addr, vi[k], vi[k + 1]);
        else if (bytes === 4) mem.st32(addr, vi[k]);
        else if (bytes === 2) mem.st16(addr, vi[k]);
        else mem.st8(addr, vi[k]);
        return;
      }
      if (opc !== 1) return;
      if (bytes === 8) {
        vi[k] = mem.ld64(addr, this.t1);
        vi[k + 1] = this.t1[0];
      } else {
        vi[k] = bytes === 4 ? mem.ld32(addr) : bytes === 2 ? mem.ld16(addr) : mem.ld8(addr);
        vi[k + 1] = 0;
      }
      vi[k + 2] = 0;
      vi[k + 3] = 0;
      return;
    }
    if (opc === 0) {
      const lo = rt === 31 ? 0 : this.xlo[rt];
      const hi = rt === 31 ? 0 : this.xhi[rt];
      if (size === 3) mem.st64(addr, lo, hi);
      else if (size === 2) mem.st32(addr, lo);
      else if (size === 1) mem.st16(addr, lo);
      else mem.st8(addr, lo);
      return;
    }
    if (opc === 1) {
      if (size === 3) {
        const lo = mem.ld64(addr, this.t1);
        if (rt !== 31) {
          this.xlo[rt] = lo;
          this.xhi[rt] = this.t1[0];
        }
      } else {
        const v = size === 2 ? mem.ld32(addr) : size === 1 ? mem.ld16(addr) : mem.ld8(addr);
        if (rt !== 31) {
          this.xlo[rt] = v;
          this.xhi[rt] = 0;
        }
      }
      return;
    }
    if (size === 3) return; // PRFM
    const lo = size === 2 ? mem.ld32(addr) : size === 1 ? (mem.ld16(addr) << 16) >> 16 : (mem.ld8(addr) << 24) >> 24;
    if (rt === 31) return;
    this.xlo[rt] = lo;
    this.xhi[rt] = size === 2 ? lo >> 31 : 0;
  }

  /** 成对访存（number 版） */
  private ldstPairN(w: number, base: number, imm: number, idx: number, rn: number): void {
    const opc = w >>> 30;
    const L = (w >>> 22) & 1;
    const V = (w >>> 26) & 1;
    const bytes = V === 1 ? 4 << opc : (opc === 2 ? 8 : 4);
    const rt = w & 31;
    const rt2 = (w >>> 10) & 31;
    const addr = idx === 1 ? base : base + imm;
    const mem = this.mem;
    const vi = this.vi;
    if (L === 1) {
      if (V === 1) {
        if (bytes === 16) {
          let k = rt * 4;
          vi[k] = mem.ld64(addr, this.t1);
          vi[k + 1] = this.t1[0];
          vi[k + 2] = mem.ld64(addr + 8, this.t1);
          vi[k + 3] = this.t1[0];
          k = rt2 * 4;
          vi[k] = mem.ld64(addr + 16, this.t1);
          vi[k + 1] = this.t1[0];
          vi[k + 2] = mem.ld64(addr + 24, this.t1);
          vi[k + 3] = this.t1[0];
        } else {
          let k = rt * 4;
          if (bytes === 8) {
            vi[k] = mem.ld64(addr, this.t1);
            vi[k + 1] = this.t1[0];
          } else {
            vi[k] = mem.ld32(addr);
            vi[k + 1] = 0;
          }
          vi[k + 2] = 0;
          vi[k + 3] = 0;
          k = rt2 * 4;
          if (bytes === 8) {
            vi[k] = mem.ld64(addr + bytes, this.t1);
            vi[k + 1] = this.t1[0];
          } else {
            vi[k] = mem.ld32(addr + bytes);
            vi[k + 1] = 0;
          }
          vi[k + 2] = 0;
          vi[k + 3] = 0;
        }
      } else if (opc === 2) {
        if (rt !== 31) {
          this.xlo[rt] = mem.ld64(addr, this.t1);
          this.xhi[rt] = this.t1[0];
        }
        if (rt2 !== 31) {
          this.xlo[rt2] = mem.ld64(addr + 8, this.t1);
          this.xhi[rt2] = this.t1[0];
        }
      } else {
        const a = mem.ld32(addr);
        const b = mem.ld32(addr + 4);
        if (rt !== 31) {
          this.xlo[rt] = a;
          this.xhi[rt] = opc === 1 ? a >> 31 : 0;
        }
        if (rt2 !== 31) {
          this.xlo[rt2] = b;
          this.xhi[rt2] = opc === 1 ? b >> 31 : 0;
        }
      }
    } else if (V === 1) {
      if (bytes === 16) {
        const k = rt * 4;
        const k2 = rt2 * 4;
        mem.st64(addr, vi[k], vi[k + 1]);
        mem.st64(addr + 8, vi[k + 2], vi[k + 3]);
        mem.st64(addr + 16, vi[k2], vi[k2 + 1]);
        mem.st64(addr + 24, vi[k2 + 2], vi[k2 + 3]);
      } else if (bytes === 8) {
        mem.st64(addr, vi[rt * 4], vi[rt * 4 + 1]);
        mem.st64(addr + 8, vi[rt2 * 4], vi[rt2 * 4 + 1]);
      } else {
        mem.st32(addr, vi[rt * 4]);
        mem.st32(addr + 4, vi[rt2 * 4]);
      }
    } else if (bytes === 8) {
      mem.st64(addr, rt === 31 ? 0 : this.xlo[rt], rt === 31 ? 0 : this.xhi[rt]);
      mem.st64(addr + 8, rt2 === 31 ? 0 : this.xlo[rt2], rt2 === 31 ? 0 : this.xhi[rt2]);
    } else {
      mem.st32(addr, rt === 31 ? 0 : this.xlo[rt]);
      mem.st32(addr + 4, rt2 === 31 ? 0 : this.xlo[rt2]);
    }
    if (idx === 1 || idx === 3) this.sxNumS(rn, base + imm);
  }

  /**
   * 热路径解释器：覆盖 99.9% 的指令（按直方图），全部走 number 运算。
   * 其余指令类转发给 execSlow。
   */
  exec(c: number, w: number): void {
    if (this.slowCls[c] === 1) {
      this.execSlow(c, w);
      return;
    }
    if (this.verifyOn && Cpu.fastHas[c] === 1) {
      this.execVerify(c, w);
      return;
    }
    this.execFast(c, w);
  }

  /** 调试：快慢两条路径各跑一次，比较寄存器/标志/内存侧状态 */
  private execVerify(c: number, w: number): void {
    const slo = this.xlo.slice();
    const shi = this.xhi.slice();
    const svi = this.vi.slice();
    const snzcv = this.nzcv;
    const spc = this.pc;
    const smon = this.monAddr;
    this.mem.wlog = [];
    this.execFast(c, w);
    const fastLog = this.mem.wlog;
    this.mem.wlog = [];
    const flo = this.xlo.slice();
    const fhi = this.xhi.slice();
    const fvi = this.vi.slice();
    const fnzcv = this.nzcv;
    const fpc = this.pc;
    const fmon = this.monAddr;
    this.xlo.set(slo);
    this.xhi.set(shi);
    this.vi.set(svi);
    this.nzcv = snzcv;
    this.pc = spc;
    this.monAddr = smon;
    this.execSlow(c, w);
    const slowLog = this.mem.wlog!;
    this.mem.wlog = null;
    const where = `pc=0x${(spc - 4).toString(16)} cls=${c} w=0x${(w >>> 0).toString(16)}`;
    if (fastLog!.length !== slowLog.length) {
      console.error(`VERIFY ${where} 写内存次数 fast=${JSON.stringify(fastLog)} slow=${JSON.stringify(slowLog)}`);
      throw new Error(`${where} 写内存次数 fast=${fastLog!.length / 4} slow=${slowLog.length / 4}`);
    }
    for (let i = 0; i < slowLog.length; i++) {
      if (fastLog![i] !== slowLog[i]) {
        console.error(`VERIFY ${where} 写内存差异 @${i} fast=${JSON.stringify(fastLog)} slow=${JSON.stringify(slowLog)} x2snap=${shi[2] >>> 0}:${slo[2] >>> 0} x2slow=${this.xhi[2] >>> 0}:${this.xlo[2] >>> 0}`);
        throw new Error(`${where} 写内存差异 @${i}`);
      }
    }
    for (let i = 0; i < 32; i++) {
      if (flo[i] !== this.xlo[i] || fhi[i] !== this.xhi[i]) {
        throw new Error(`${where} x${i} fast=${fhi[i] >>> 0}:${flo[i] >>> 0} slow=${this.xhi[i] >>> 0}:${this.xlo[i] >>> 0}`);
      }
    }
    for (let i = 0; i < 64; i++) {
      if (fvi[i] !== this.vi[i]) {
        throw new Error(`${where} v[${i >> 2}].w${i & 3} fast=${fvi[i] >>> 0} slow=${this.vi[i] >>> 0}`);
      }
    }
    if (fnzcv !== this.nzcv) throw new Error(`${where} nzcv fast=${fnzcv} slow=${this.nzcv}`);
    if (fpc !== this.pc) throw new Error(`${where} pc fast=0x${fpc.toString(16)} slow=0x${this.pc.toString(16)}`);
    if (fmon !== this.monAddr) throw new Error(`${where} monAddr fast=0x${fmon.toString(16)} slow=0x${this.monAddr.toString(16)}`);
  }

  /** 快路径（number 版）主体 */
  private execFast(c: number, w: number): void {
    switch (c) {
      case C_MOVEWIDE: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const hw = (w >>> 21) & 3;
        const imm16 = (w >>> 5) & 0xffff;
        const rd = w & 31;
        const shift = hw * 16;
        if (opc === 2) {
          // MOVZ
          if (shift < 32) this.sx32(rd, imm16 << shift);
          else if (rd !== 31) {
            this.xlo[rd] = 0;
            this.xhi[rd] = imm16 << (shift - 32);
          }
          return;
        }
        if (opc === 0) {
          // MOVN
          let vlo = 0;
          let vhi = 0;
          if (shift < 32) {
            vlo = imm16 << shift;
            vhi = shift === 0 ? 0 : imm16 >>> (32 - shift);
          } else {
            vhi = imm16 << (shift - 32);
          }
          this.rlo = ~vlo;
          this.rhi = sf === 1 ? ~vhi : 0;
          this.sx(rd);
          return;
        }
        if (opc === 3) {
          // MOVK
          const cl = rd === 31 ? 0 : this.xlo[rd];
          const ch = rd === 31 || sf === 0 ? 0 : this.xhi[rd];
          if (shift < 32) {
            this.rlo = (cl & ~(0xffff << shift)) | (imm16 << shift);
            this.rhi = ch;
          } else {
            this.rlo = cl;
            this.rhi = (ch & ~(0xffff << (shift - 32))) | (imm16 << (shift - 32));
          }
          this.sx(rd);
          return;
        }
        this.execSlow(c, w);
        return;
      }
      case C_LOGIC_SHIFT: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const shift = (w >>> 22) & 3;
        const N = (w >>> 21) & 1;
        const imm6 = (w >>> 10) & 0x3f;
        const rm = (w >>> 16) & 31;
        this.gx(rm);
        this.shiftN(shift, imm6, sf);
        if (N === 1) {
          this.rlo = ~this.rlo;
          if (sf === 1) this.rhi = ~this.rhi;
        }
        const bLo = this.rlo;
        const bHi = this.rhi;
        this.gx((w >>> 5) & 31);
        const aLo = this.rlo;
        const aHi = this.rhi;
        let lo: number;
        let hi: number;
        if (opc === 0) { lo = aLo & bLo; hi = aHi & bHi; }
        else if (opc === 1) { lo = aLo | bLo; hi = aHi | bHi; }
        else if (opc === 2) { lo = aLo ^ bLo; hi = aHi ^ bHi; }
        else { lo = aLo & bLo; hi = aHi & bHi; }
        const rd = w & 31;
        if (sf === 0) hi = 0;
        if (opc === 3) {
          this.nzcv = ((hi >>> 31) << 3) | (((lo | hi) === 0 ? 1 : 0) << 2);
          this.sx32(rd, lo);
        } else {
          this.rlo = lo;
          this.rhi = hi;
          this.sx(rd);
        }
        return;
      }
      case C_LDST_UOFF: {
        const rn = (w >>> 5) & 31;
        this.ldstOneN(w, this.num(rn) + ((w >>> 10) & 0xfff) * this.ldstBytes(w));
        return;
      }
      case C_BITFIELD: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const immr = (w >>> 16) & 0x3f;
        const imms = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const dsz = sf === 1 ? 64 : 32;
        const slo = rn === 31 ? 0 : this.xlo[rn];
        const shi = sf === 1 && rn !== 31 ? this.xhi[rn] : 0;
        let width: number;
        let lsb: number;
        if (imms >= immr) {
          width = imms - immr + 1;
          lsb = 0;
          this.extractN(slo, shi, immr, width);
        } else {
          width = imms + 1;
          lsb = dsz - immr;
          this.extractN(slo, shi, 0, width);
        }
        if (opc === 0 && width < dsz) {
          // SBFM：按第 width-1 位做符号扩展
          const bitv = width <= 32 ? (this.rlo >>> (width - 1)) & 1 : (this.rhi >>> (width - 33)) & 1;
          if (bitv === 1) {
            if (width < 32) { this.rlo |= ~((1 << width) - 1); this.rhi = -1; }
            else if (width === 32) this.rhi = -1;
            else this.rhi |= ~((1 << (width - 32)) - 1);
          }
        }
        if (opc === 0 || opc === 2) {
          this.shiftN(0, lsb, sf);
          this.sx(rd);
          return;
        }
        // BFM：保留 rd 目标字段之外的位
        this.shiftN(0, lsb, sf);
        const xLo = this.rlo;
        const xHi = this.rhi;
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
          this.xlo[rd] = xLo | (this.xlo[rd] & ~mLo);
          this.xhi[rd] = sf === 1 ? xHi | (this.xhi[rd] & ~mHi) : 0;
        }
        return;
      }
      case C_ADDSUB_SHIFT: {
        const sf = w >>> 31;
        const sub = ((w >>> 30) & 1) === 1;
        const setF = ((w >>> 29) & 1) === 1;
        const shift = (w >>> 22) & 3;
        const rm = (w >>> 16) & 31;
        this.gx(rm);
        this.shiftN(shift, (w >>> 10) & 0x3f, sf);
        const bLo = this.rlo;
        const bHi = this.rhi;
        this.gx((w >>> 5) & 31);
        this.addsubN(bLo, bHi, sub, sf, setF);
        if (setF) {
          if (sf === 1) this.sx(w & 31);
          else this.sx32(w & 31, this.rlo);
        } else this.sx(w & 31);
        return;
      }
      case C_LOGIC_IMM: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        this.decodeBitMasksNum((w >>> 22) & 1, (w >>> 10) & 0x3f, (w >>> 16) & 0x3f, sf);
        const rn = (w >>> 5) & 31;
        this.gx(rn);
        const aLo = this.rlo;
        const aHi = this.rhi;
        let lo: number;
        let hi: number;
        if (opc === 0) { lo = aLo & this.bmLo; hi = aHi & this.bmHi; }
        else if (opc === 1) { lo = aLo | this.bmLo; hi = aHi | this.bmHi; }
        else if (opc === 2) { lo = aLo ^ this.bmLo; hi = aHi ^ this.bmHi; }
        else { lo = aLo & this.bmLo; hi = aHi & this.bmHi; }
        if (sf === 0) hi = 0;
        const rd = w & 31;
        if (opc === 3) {
          this.nzcv = ((hi >>> 31) << 3) | (((lo | hi) === 0 ? 1 : 0) << 2);
          this.sx32(rd, lo);
        } else {
          this.rlo = lo;
          this.rhi = hi;
          this.sx(rd);
        }
        return;
      }
      case C_LDST_UNSCALED: {
        const rn = (w >>> 5) & 31;
        const off = (((w >>> 12) & 0x1ff) << 23) >> 23;
        this.ldstOneN(w, this.num(rn) + off);
        return;
      }
      case C_LDST_ROFF: {
        const rn = (w >>> 5) & 31;
        const size = w >>> 30;
        const S = (w >>> 12) & 1;
        const bytes = this.ldstBytes(w);
        const shift = S === 1 ? (bytes === 16 ? 4 : size) : 0;
        this.gx((w >>> 16) & 31);
        this.extendN((w >>> 13) & 7, shift, 1);
        const addr = this.num(rn) + this.rhi * 4294967296 + (this.rlo >>> 0);
        this.ldstOneN(w, addr);
        return;
      }
      case C_ADDSUB_IMM: {
        const sf = w >>> 31;
        const sub = ((w >>> 30) & 1) === 1;
        const setF = ((w >>> 29) & 1) === 1;
        const sh = (w >>> 22) & 1;
        const imm = ((w >>> 10) & 0xfff) << (sh === 1 ? 12 : 0);
        this.gxs((w >>> 5) & 31);
        this.addsubN(imm, 0, sub, sf, setF);
        if (setF) {
          if (sf === 1) this.sx(w & 31);
          else this.sx32(w & 31, this.rlo);
        } else this.sxs(w & 31);
        return;
      }
      case C_ADR: {
        const imm = (((w >> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
        const off = (imm << 11) >> 11;
        const pc0 = this.pc - 4;
        this.sxNum(w & 31, w >>> 31 === 1 ? (pc0 & ~0xfff) + off * 4096 : pc0 + off);
        return;
      }
      case C_BR: {
        this.pc = this.num((w >>> 5) & 31);
        return;
      }
      case C_LDST_PRE: {
        const rn = (w >>> 5) & 31;
        const off = (((w >>> 12) & 0x1ff) << 23) >> 23;
        const base = this.num(rn) + off;
        this.sxNumS(rn, base);
        this.ldstOneN(w, base);
        return;
      }
      case C_BCOND: {
        if (this.cond(w & 0xf)) {
          const off = (((w >>> 5) & 0x7ffff) << 13) >> 13;
          this.pc = this.pc - 4 + off * 4;
        }
        return;
      }
      case C_ADDSUB_EXT: {
        const sf = w >>> 31;
        const sub = ((w >>> 30) & 1) === 1;
        const setF = ((w >>> 29) & 1) === 1;
        this.gx((w >>> 16) & 31);
        this.extendN((w >>> 13) & 7, (w >>> 10) & 7, sf);
        const bLo = this.rlo;
        const bHi = this.rhi;
        this.gxs((w >>> 5) & 31);
        this.addsubN(bLo, bHi, sub, sf, setF);
        if (setF) {
          if (sf === 1) this.sx(w & 31);
          else this.sx32(w & 31, this.rlo);
        } else this.sxs(w & 31);
        return;
      }
      case C_VEC_LOGIC: {
        const Q = (w >>> 30) & 1;
        const op = (((w >>> 29) & 1) << 2) | ((w >>> 22) & 3);
        const k = (w & 31) * 4;
        const an = ((w >>> 5) & 31) * 4;
        const am = ((w >>> 16) & 31) * 4;
        const vi = this.vi;
        const a0 = vi[an];
        const a1 = vi[an + 1];
        const a2 = vi[an + 2];
        const a3 = vi[an + 3];
        const b0 = vi[am];
        const b1 = vi[am + 1];
        const b2 = vi[am + 2];
        const b3 = vi[am + 3];
        let lo0: number;
        let lo1: number;
        let hi0: number;
        let hi1: number;
        if (op === 0) {
          lo0 = a0 & b0; lo1 = a1 & b1; hi0 = a2 & b2; hi1 = a3 & b3;
        } else if (op === 1) {
          lo0 = a0 & ~b0; lo1 = a1 & ~b1; hi0 = a2 & ~b2; hi1 = a3 & ~b3;
        } else if (op === 2) {
          lo0 = a0 | b0; lo1 = a1 | b1; hi0 = a2 | b2; hi1 = a3 | b3;
        } else if (op === 3) {
          lo0 = a0 | ~b0; lo1 = a1 | ~b1; hi0 = a2 | ~b2; hi1 = a3 | ~b3;
        } else if (op === 4) {
          lo0 = a0 ^ b0; lo1 = a1 ^ b1; hi0 = a2 ^ b2; hi1 = a3 ^ b3;
        } else {
          const d0 = vi[k];
          const d1 = vi[k + 1];
          const d2 = vi[k + 2];
          const d3 = vi[k + 3];
          if (op === 5 || op === 6) {
            lo0 = (a0 & b0) | (~a0 & d0);
            lo1 = (a1 & b1) | (~a1 & d1);
            hi0 = (a2 & b2) | (~a2 & d2);
            hi1 = (a3 & b3) | (~a3 & d3);
          } else {
            lo0 = (a0 & d0) | (~a0 & b0);
            lo1 = (a1 & d1) | (~a1 & b1);
            hi0 = (a2 & d2) | (~a2 & b2);
            hi1 = (a3 & d3) | (~a3 & b3);
          }
        }
        vi[k] = lo0;
        vi[k + 1] = lo1;
        if (Q === 1) {
          vi[k + 2] = hi0;
          vi[k + 3] = hi1;
        } else {
          vi[k + 2] = 0;
          vi[k + 3] = 0;
        }
        return;
      }
      case C_VEC_UMOV: {
        const Q = (w >>> 30) & 1;
        const lane = this.imm5ToLane((w >>> 16) & 0x1f);
        this.laneN((w >>> 5) & 31, lane.index, lane.esize);
        const rd = w & 31;
        if (rd !== 31) {
          this.xlo[rd] = this.rlo;
          this.xhi[rd] = lane.esize === 64 && Q === 1 ? this.rhi : 0;
        }
        return;
      }
      case C_BBL: {
        const off = ((w & 0x3ffffff) << 6) >> 6;
        if ((w >>> 31) === 1) this.sxNum(30, this.pc);
        this.pc = this.pc - 4 + off * 4;
        return;
      }
      case C_CSEL: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const rm = (w >>> 16) & 31;
        const op2 = (w >>> 10) & 3;
        const rd = w & 31;
        if (this.cond((w >>> 12) & 0xf)) {
          this.gx((w >>> 5) & 31);
        } else {
          this.gx(rm);
          if (op === 0) {
            if (op2 === 1) {
              if (sf === 1) {
                const s = (this.rlo >>> 0) + 1;
                this.rlo = s | 0;
                if (s > 0xffffffff) this.rhi = (this.rhi + 1) | 0;
              } else {
                this.rlo = (this.rlo + 1) | 0;
              }
            }
          } else if (op2 === 0) {
            this.rlo = ~this.rlo;
            if (sf === 1) this.rhi = ~this.rhi;
          } else if (sf === 1) {
            const s = (this.rlo >>> 0) === 0 ? 1 : 0;
            this.rlo = (~this.rlo + 1) | 0;
            this.rhi = (~this.rhi + s) | 0;
          } else {
            this.rlo = (~this.rlo + 1) | 0;
          }
        }
        if (sf === 0) this.rhi = 0;
        this.sxs(rd);
        return;
      }
      case C_PAIR: {
        const rn = (w >>> 5) & 31;
        const raw = (w >>> 15) & 0x7f;
        const opc = w >>> 30;
        const V = (w >>> 26) & 1;
        const scale = V === 1 ? 4 << opc : (opc === 2 ? 8 : 4);
        this.ldstPairN(w, this.num(rn), ((raw << 25) >> 25) * scale, (w >>> 23) & 3, rn);
        return;
      }
      case C_FMOV_WS: {
        const k = ((w >>> 5) & 31) * 4;
        this.sx32(w & 31, this.vi[k]);
        return;
      }
      case C_VEC_DUP_GEN: {
        const Q = (w >>> 30) & 1;
        const lane = this.imm5ToLane((w >>> 16) & 0x1f);
        const esize = lane.esize;
        this.gx((w >>> 5) & 31);
        let lo: number;
        let hi: number;
        if (esize === 64) {
          lo = this.rlo;
          hi = this.rhi;
        } else {
          const v = this.rlo & (esize === 32 ? -1 : (1 << esize) - 1);
          if (esize === 32) { lo = v; hi = v; }
          else if (esize === 16) { lo = (v | (v << 16)) | 0; hi = lo; }
          else { lo = (v * 0x01010101) | 0; hi = lo; }
        }
        const k = (w & 31) * 4;
        const vi = this.vi;
        vi[k] = lo;
        vi[k + 1] = hi;
        vi[k + 2] = Q === 1 ? lo : 0;
        vi[k + 3] = Q === 1 ? hi : 0;
        return;
      }
      case C_VEC_DUP_EL: {
        const Q = (w >>> 30) & 1;
        const lane = this.imm5ToLane((w >>> 16) & 0x1f);
        const esize = lane.esize;
        this.laneN((w >>> 5) & 31, lane.index, esize);
        let lo: number;
        let hi: number;
        if (esize === 64) {
          lo = this.rlo;
          hi = this.rhi;
        } else {
          const v = this.rlo;
          if (esize === 32) { lo = v; hi = v; }
          else if (esize === 16) { lo = (v | (v << 16)) | 0; hi = lo; }
          else { lo = (v * 0x01010101) | 0; hi = lo; }
        }
        const k = (w & 31) * 4;
        const vi = this.vi;
        vi[k] = lo;
        vi[k + 1] = hi;
        vi[k + 2] = Q === 1 ? lo : 0;
        vi[k + 3] = Q === 1 ? hi : 0;
        return;
      }
      case C_CBZ: {
        const rt = w & 31;
        const sf = w >>> 31;
        const v = rt === 31 ? 0 : sf === 1 ? this.xlo[rt] | this.xhi[rt] : this.xlo[rt];
        const nz = (w >>> 24) & 1;
        if ((v === 0) !== (nz === 1)) {
          const off = (((w >>> 5) & 0x7ffff) << 13) >> 13;
          this.pc = this.pc - 4 + off * 4;
        }
        return;
      }
      case C_TBZ: {
        const bit = (((w >>> 31) & 1) << 5) | ((w >>> 19) & 0x1f);
        const rt = w & 31;
        const v = rt === 31
          ? 0
          : bit < 32 ? (this.xlo[rt] >>> bit) & 1 : (this.xhi[rt] >>> (bit - 32)) & 1;
        const nz = (w >>> 24) & 1;
        if (v === nz) {
          const off = (((w >>> 5) & 0x3fff) << 18) >> 18;
          this.pc = this.pc - 4 + off * 4;
        }
        return;
      }
      case C_RET:
      case C_BLR: {
        // ARM64 先读目标寄存器再写 X30，因此 blr x30 必须跳到旧值
        const t = this.num((w >>> 5) & 31);
        if (c === C_BLR) this.sxNum(30, this.pc);
        this.pc = t;
        return;
      }
      case C_LDST_POST: {
        const rn = (w >>> 5) & 31;
        const off = (((w >>> 12) & 0x1ff) << 23) >> 23;
        const base = this.num(rn);
        this.ldstOneN(w, base);
        this.sxNumS(rn, base + off);
        return;
      }
      case C_LDST_LIT: {
        const off = (((w >>> 5) & 0x7ffff) << 13) >> 13;
        this.ldstOneN(w, this.pc - 4 + off * 4);
        return;
      }
      case C_EXTR: {
        const sf = w >>> 31;
        const rm = (w >>> 16) & 31;
        const lsb = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        this.gx(rm);
        const bLo = this.rlo;
        const bHi = this.rhi;
        this.gx(rn);
        const aLo = this.rlo;
        const aHi = this.rhi;
        const rd = w & 31;
        if (sf === 0) {
          const n = lsb & 31;
          this.rlo = n === 0 ? bLo : (bLo >>> n) | (aLo << (32 - n));
          this.rhi = 0;
        } else if (lsb === 0) {
          this.rlo = bLo;
          this.rhi = bHi;
        } else if (lsb < 32) {
          this.rlo = (bLo >>> lsb) | (bHi << (32 - lsb));
          this.rhi = (bHi >>> lsb) | (aLo << (32 - lsb));
        } else if (lsb === 32) {
          this.rlo = bHi;
          this.rhi = aLo;
        } else {
          const m = lsb - 32;
          this.rlo = (bHi >>> m) | (aLo << (32 - m));
          this.rhi = (aLo >>> m) | (aHi << (32 - m));
        }
        this.sx(rd);
        return;
      }
      case C_CCMP:
      case C_CCMP_IMM: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        if (!this.cond((w >>> 12) & 0xf)) {
          this.nzcv = w & 0xf;
          return;
        }
        if (c === C_CCMP_IMM) {
          this.gx((w >>> 5) & 31);
          this.addsubN((w >>> 16) & 0x1f, 0, op === 1, sf, true);
        } else {
          this.gx((w >>> 16) & 31);
          const bLo = this.rlo;
          const bHi = this.rhi;
          this.gx((w >>> 5) & 31);
          this.addsubN(bLo, bHi, op === 1, sf, true);
        }
        return;
      }
      case C_LDAR:
      case C_STLR: {
        const rn = (w >>> 5) & 31;
        const addr = rn === 31 ? 0 : this.num(rn);
        const rt = w & 31;
        const size = w >>> 30;
        if (c === C_LDAR) {
          if (rt !== 31) {
            if (size === 3) {
              this.xlo[rt] = this.mem.ld64(addr, this.t1);
              this.xhi[rt] = this.t1[0];
            } else {
              this.xlo[rt] = size === 2 ? this.mem.ld32(addr) : size === 1 ? this.mem.ld16(addr) : this.mem.ld8(addr);
              this.xhi[rt] = 0;
            }
          }
        } else if (size === 3) {
          this.mem.st64(addr, this.xlo[rt], this.xhi[rt]);
        } else if (size === 2) {
          this.mem.st32(addr, this.xlo[rt]);
        } else if (size === 1) {
          this.mem.st16(addr, this.xlo[rt]);
        } else {
          this.mem.st8(addr, this.xlo[rt]);
        }
        return;
      }
      case C_CLREX:
      case C_PAC:
      case C_XPACLRI:
      case C_BTI:
      case C_HINT:
      case C_BARRIER:
        return;
      default:
        this.execSlow(c, w);
    }
  }

  /** 慢路径：冷门指令类（保留 BigInt 实现，经 cpu.x Proxy 读写） */
  private execSlow(c: number, w: number): void {
    switch (c) {
      case C_ADR: {
        // imm = immhi:immlo（21 位），ADR 直接作为字节偏移；ADRP 左移 12 位并页对齐
        const imm = (((w >> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
        const off = BigInt.asIntN(21, BigInt(imm));
        const pc = BigInt(this.pc - 4);
        const v = (w >>> 31) === 1
          ? (pc & ~0xfffn) + (off << 12n)
          : pc + off;
        this.wx(w & 31, v & MASK64);
        return;
      }
      case C_ADDSUB_IMM: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const S = (w >>> 29) & 1;
        const sh = (w >>> 22) & 1;
        const imm12 = (w >>> 10) & 0xfff;
        const imm = BigInt(sh ? imm12 << 12 : imm12);
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const r = this.addsub(this.rxn(rn), imm, op === 1, sf, S === 1);
        if (S === 1) this.wx(rd, r);
        else this.wxn(rd, r);
        return;
      }
      case C_LOGIC_IMM: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const N = (w >>> 22) & 1;
        const immr = (w >>> 16) & 0x3f;
        const imms = (w >>> 10) & 0x3f;
        const imm = this.decodeBitMasks(N, imms, immr, sf);
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const M = sf ? MASK64 : MASK32;
        const a = this.rx(rn) & M;
        let r: bigint;
        if (opc === 0) r = a & imm;
        else if (opc === 1) r = a | imm;
        else if (opc === 2) r = a ^ imm;
        else {
          r = a & imm;
          this.nzcv = this.nz(r, sf);
        }
        r &= M;
        if (opc === 3) this.wx(rd, r);
        else this.wxn(rd, r);
        return;
      }
      case C_MOVEWIDE: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const hw = (w >>> 21) & 3;
        const imm16 = BigInt((w >>> 5) & 0xffff);
        const shift = BigInt(hw * 16);
        const rd = w & 31;
        const M = sf ? MASK64 : MASK32;
        let r: bigint;
        if (opc === 0) r = ~(imm16 << shift) & M;
        else if (opc === 2) r = (imm16 << shift) & M;
        else {
          const mask = 0xffffn << shift;
          r = (this.rx(rd) & ~mask & M) | ((imm16 << shift) & M);
        }
        this.wx(rd, r);
        return;
      }
      case C_BITFIELD: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const immr = (w >>> 16) & 0x3f;
        const imms = (w >>> 10) & 0x3f;
        const dsz = sf ? 64 : 32;
        const M = sf ? MASK64 : MASK32;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const src = this.rx(rn) & M;
        let width: number;
        let lsb: number;
        let val: bigint;
        if (imms >= immr) {
          width = imms - immr + 1;
          val = (src >> BigInt(immr)) & ((1n << BigInt(width)) - 1n);
          lsb = 0;
        } else {
          width = imms + 1;
          val = src & ((1n << BigInt(width)) - 1n);
          lsb = dsz - immr;
        }
        if (opc === 0) {
          if ((val >> BigInt(width - 1)) & 1n) val |= M ^ ((1n << BigInt(width)) - 1n);
          this.wx(rd, (val << BigInt(lsb)) & M);
        } else if (opc === 2) {
          this.wx(rd, (val << BigInt(lsb)) & M);
        } else {
          const fieldMask = (((1n << BigInt(width)) - 1n) << BigInt(lsb)) & M;
          const r = ((val << BigInt(lsb)) & M) | (this.rx(rd) & (M ^ fieldMask));
          this.wx(rd, r);
        }
        return;
      }
      case C_EXTR: {
        const sf = w >>> 31;
        const Rm = (w >>> 16) & 31;
        const lsb = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const bits = sf ? 64 : 32;
        const M = sf ? MASK64 : MASK32;
        const a = this.rx(rn) & M;
        const b = this.rx(Rm) & M;
        // EXTR：Rn 是高半、Rm 是低半，即 concat(Rn,Rm) >> lsb
        let r: bigint;
        if (lsb === 0) r = b;
        else r = ((b >> BigInt(lsb)) | (a << BigInt(bits - lsb))) & M;
        this.wx(rd, r);
        return;
      }
      // ------------------------------------------------------------ 分支
      case C_BBL: {
        const off = BigInt.asIntN(26, BigInt(w & 0x3ffffff)) << 2n;
        const target = Number(BigInt(this.pc - 4) + off);
        // bit31 = 1 是 BL（写 LR），0 是 B；step 后 pc 已是下一条指令
        if (w >>> 31) this.x[30] = BigInt(this.pc);
        this.pc = target;
        return;
      }
      case C_BCOND: {
        const cond = w & 0xf;
        const off = BigInt.asIntN(19, BigInt((w >>> 5) & 0x7ffff)) << 2n;
        if (this.cond(cond)) this.pc = Number(BigInt(this.pc - 4) + off);
        return;
      }
      case C_CBZ: {
        const sf = w >>> 31;
        const nz = (w >>> 24) & 1;
        const off = BigInt.asIntN(19, BigInt((w >>> 5) & 0x7ffff)) << 2n;
        const t = this.rx(w & 31) & (sf ? MASK64 : MASK32);
        if ((t === 0n) !== (nz === 1)) this.pc = Number(BigInt(this.pc - 4) + off);
        return;
      }
      case C_TBZ: {
        const nz = (w >>> 24) & 1;
        const bit = (((w >>> 31) & 1) << 5) | ((w >>> 19) & 0x1f);
        const off = BigInt.asIntN(14, BigInt((w >>> 5) & 0x3fff)) << 2n;
        const t = this.rx(w & 31);
        const set = ((t >> BigInt(bit)) & 1n) === 1n;
        // TBNZ(op=1) 位为 1 跳转；TBZ(op=0) 位为 0 跳转
        if (set === (nz === 1)) this.pc = Number(BigInt(this.pc - 4) + off);
        return;
      }
      case C_BR: {
        this.pc = Number(this.rx((w >>> 5) & 31));
        return;
      }
      case C_BLR: {
        const t = Number(this.rx((w >>> 5) & 31));
        this.x[30] = BigInt(this.pc);
        this.pc = t;
        return;
      }
      case C_RET: {
        this.pc = Number(this.rx((w >>> 5) & 31));
        return;
      }
      // ------------------------------------------------------------ 系统
      case C_SVC: {
        if (this.svc) this.svc(this, (w >>> 5) & 0xffff);
        else throw new Error(`未提供 svc 处理器 @0x${(this.pc - 4).toString(16)}`);
        return;
      }
      case C_BRK: {
        throw new Error(`brk #${(w >>> 5) & 0xffff} @0x${(this.pc - 4).toString(16)}`);
      }
      case C_MRS:
      case C_MSRREG: {
        const isRead = c === C_MRS;
        const key = (w >>> 5) & 0xffff;
        const rt = w & 31;
        if (this.sysReg && this.sysReg(this, isRead, key, rt)) return;
        // 默认语义：只处理常见的几个
        if (isRead) {
          if (key === 0xda10) this.wx(rt, BigInt(this.nzcv));
          else if (key === 0xde82) this.wx(rt, this.tpidr);
          else if (key === 0xdf02) this.wx(rt, this.cntvct());
          // DCZID_EL0：块大小 2^4 个 word（64 字节），且允许 DC ZVA
          else if (key === 0xd807) this.wx(rt, 4n);
          else throw new Error(`未知 MRS 系统寄存器 0x${key.toString(16)}`);
        } else if (key === 0xda10) {
          this.nzcv = Number(this.rx(rt) & 0xfn);
        } else if (key === 0x5ba1) {
          // DC ZVA：把 64 字节对齐块清零
          const a = Math.floor(Number(this.rx(rt)) / 64) * 64;
          for (let i = 0; i < 64; i += 8) this.st(a + i, 8, 0n);
        } else {
          throw new Error(`未知 MSR 系统寄存器 0x${key.toString(16)}`);
        }
        return;
      }
      case C_CLREX:
      case C_PAC:
      case C_XPACLRI:
      case C_BTI:
      case C_HINT:
      case C_BARRIER: {
        return;
      }
      // ------------------------------------------------------------ 原子
      case C_LDAR: {
        const size = w >>> 30;
        const bytes = 1 << size;
        const addr = Number(this.rx((w >>> 5) & 31));
        this.wx(w & 31, this.ld(addr, bytes));
        return;
      }
      case C_LDXR:
      case C_LDAXR: {
        const size = w >>> 30;
        const bytes = 1 << size;
        const addr = Number(this.rx((w >>> 5) & 31));
        this.wx(w & 31, this.ld(addr, bytes));
        this.monAddr = addr;
        this.monSize = bytes;
        return;
      }
      case C_STLR: {
        const size = w >>> 30;
        const bytes = 1 << size;
        const addr = Number(this.rx((w >>> 5) & 31));
        this.st(addr, bytes, this.rx(w & 31));
        return;
      }
      case C_STXR:
      case C_STLXR: {
        const size = w >>> 30;
        const bytes = 1 << size;
        const addr = Number(this.rx((w >>> 5) & 31));
        const ok = this.monAddr === addr && this.monSize === bytes;
        if (ok) {
          this.st(addr, bytes, this.rx(w & 31));
          this.monAddr = -1;
          this.monSize = 0;
        }
        this.wx((w >>> 16) & 31, ok ? 0n : 1n);
        return;
      }
      // ------------------------------------------------------------ 访存
      case C_PAIR: {
        const opc = w >>> 30;
        const V = (w >>> 26) & 1;
        const idx = (w >>> 23) & 3;
        const scale = V === 1 ? (4 << opc) : (opc === 2 ? 8 : 4);
        const imm = BigInt.asIntN(7, BigInt((w >>> 15) & 0x7f)) * BigInt(scale);
        this.ldstPair(w, (w >>> 5) & 31, imm, idx);
        return;
      }
      case C_LDST_UOFF: {
        const imm12 = (w >>> 10) & 0xfff;
        const addr = Number(this.rxn((w >>> 5) & 31)) + imm12 * this.ldstBytes(w);
        this.ldstOne(w, addr);
        return;
      }
      case C_LDST_ROFF: {
        const size = w >>> 30;
        const Rm = (w >>> 16) & 31;
        const option = (w >>> 13) & 7;
        const S = (w >>> 12) & 1;
        const bytes = this.ldstBytes(w);
        const shift = S === 1 ? (bytes === 16 ? 4 : size) : 0;
        const off = this.extendReg(this.rx(Rm), option, shift, 1);
        // 负偏移经符号扩展后可能是接近 2^64 的大整数，必须用 BigInt 取模后再转 number
        const addr = Number((this.rxn((w >>> 5) & 31) + off) & MASK64);
        this.ldstOne(w, addr);
        return;
      }
      case C_LDST_UNSCALED: {
        const imm = Number(BigInt.asIntN(9, BigInt((w >>> 12) & 0x1ff)));
        const addr = Number(this.rxn((w >>> 5) & 31)) + imm;
        this.ldstOne(w, addr);
        return;
      }
      case C_LDST_POST: {
        const rn = (w >>> 5) & 31;
        const imm = Number(BigInt.asIntN(9, BigInt((w >>> 12) & 0x1ff)));
        const base = Number(this.rxn(rn));
        this.ldstOne(w, base);
        this.wxn(rn, BigInt(base + imm));
        return;
      }
      case C_LDST_PRE: {
        const rn = (w >>> 5) & 31;
        const imm = Number(BigInt.asIntN(9, BigInt((w >>> 12) & 0x1ff)));
        const base = Number(this.rxn(rn)) + imm;
        this.wxn(rn, BigInt(base));
        this.ldstOne(w, base);
        return;
      }
      case C_LDST_LIT: {
        const opc = w >>> 30;
        const V = (w >>> 26) & 1;
        const off = BigInt.asIntN(19, BigInt((w >>> 5) & 0x7ffff)) << 2n;
        const addr = Number(BigInt(this.pc - 4) + off);
        const rt = w & 31;
        if (opc === 3) return; // PRFM
        if (V === 1) {
          // SIMD&FP 字面量：opc=00 → S(4B)，01 → D(8B)，10 → Q(16B)
          if (opc === 2) {
            this.setVlo(rt, this.ld(addr, 8));
            this.setVhi(rt, this.ld(addr + 8, 8));
          } else {
            this.setVlo(rt, this.ld(addr, opc === 1 ? 8 : 4));
            this.setVhi(rt, 0n);
          }
          return;
        }
        if (opc === 2) this.wx(rt, BigInt.asUintN(64, BigInt.asIntN(32, this.ld(addr, 4))));
        else this.wx(rt, this.ld(addr, opc === 1 ? 8 : 4));
        return;
      }
      // ------------------------------------------------------------ 整数（寄存器）
      case C_ADDSUB_SHIFT: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const S = (w >>> 29) & 1;
        const shift = (w >>> 22) & 3;
        const imm6 = (w >>> 10) & 0x3f;
        const b = this.shiftReg(this.rx((w >>> 16) & 31), shift, imm6, sf);
        const r = this.addsub(this.rx((w >>> 5) & 31), b, op === 1, sf, S === 1);
        if (S === 1) this.wx(w & 31, r);
        else this.wxn(w & 31, r);
        return;
      }
      case C_ADDSUB_EXT: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const S = (w >>> 29) & 1;
        const opt = (w >>> 13) & 7;
        const imm3 = (w >>> 10) & 7;
        const b = this.extendReg(this.rx((w >>> 16) & 31), opt, imm3, sf);
        const r = this.addsub(this.rx((w >>> 5) & 31), b, op === 1, sf, S === 1);
        if (S === 1) this.wx(w & 31, r);
        else this.wxn(w & 31, r);
        return;
      }
      case C_LOGIC_SHIFT: {
        const sf = w >>> 31;
        const opc = (w >>> 29) & 3;
        const shift = (w >>> 22) & 3;
        const N = (w >>> 21) & 1;
        const imm6 = (w >>> 10) & 0x3f;
        const M = sf ? MASK64 : MASK32;
        let b = this.shiftReg(this.rx((w >>> 16) & 31), shift, imm6, sf);
        if (N === 1) b = ~b & M;
        const a = this.rx((w >>> 5) & 31);
        let r: bigint;
        if (opc === 0) r = a & b;
        else if (opc === 1) r = a | b;
        else if (opc === 2) r = a ^ b;
        else r = a & b;
        r &= M;
        if (opc === 3) {
          this.nzcv = this.nz(r, sf);
          this.wx(w & 31, r);
        } else this.wxn(w & 31, r);
        return;
      }
      case C_ADDSUB_CARRY: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const S = (w >>> 29) & 1;
        const M = sf ? MASK64 : MASK32;
        const signBit = sf ? 1n << 63n : 1n << 31n;
        const a = this.rx((w >>> 5) & 31) & M;
        let b = this.rx((w >>> 16) & 31) & M;
        if (op === 1) b = ~b & M;
        const cy = (this.nzcv & F_C) !== 0 ? 1n : 0n;
        const sum = a + b + cy;
        const r = sum & M;
        if (S === 1) {
          const c = sum > M ? F_C : 0;
          const v = (~(a ^ b) & (a ^ r) & signBit) !== 0n ? F_V : 0;
          this.nzcv = this.nz(r, sf) | c | v;
        }
        if (S === 1) this.wx(w & 31, r);
        else this.wxn(w & 31, r);
        return;
      }
      case C_CSEL: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const Rm = (w >>> 16) & 31;
        const cond = (w >>> 12) & 0xf;
        const op2 = (w >>> 10) & 3;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const M = sf ? MASK64 : MASK32;
        let r: bigint;
        if (this.cond(cond)) r = this.rx(rn) & M;
        else {
          r = this.rx(Rm) & M;
          if (op === 0) {
            if (op2 === 1) r = (r + 1n) & M;
          } else {
            if (op2 === 0) r = ~r & M;
            else r = (~r + 1n) & M; // CSNEG
          }
        }
        this.wxn(rd, r);
        return;
      }
      case C_CCMP:
      case C_CCMP_IMM: {
        const sf = w >>> 31;
        const op = (w >>> 30) & 1;
        const cond = (w >>> 12) & 0xf;
        const nzcvImm = w & 0xf;
        if (!this.cond(cond)) {
          this.nzcv = nzcvImm;
          return;
        }
        const M = sf ? MASK64 : MASK32;
        const a = this.rx((w >>> 5) & 31) & M;
        const b = c === C_CCMP
          ? this.rx((w >>> 16) & 31) & M
          : BigInt((w >>> 16) & 0x1f);
        this.addsub(a, b, op === 1, sf, true);
        return;
      }
      case C_DP1: {
        const sf = w >>> 31;
        const opcode = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const M = sf ? MASK64 : MASK32;
        const bits = sf ? 64 : 32;
        const a = this.rx(rn) & M;
        let r: bigint;
        switch (opcode) {
          case 0x00: { // RBIT
            r = 0n;
            for (let i = 0; i < bits; i++) r |= ((a >> BigInt(i)) & 1n) << BigInt(bits - 1 - i);
            break;
          }
          case 0x01: { // REV16
            r = 0n;
            for (let i = 0; i < bits; i += 16) {
              const h = (a >> BigInt(i)) & 0xffffn;
              r |= (((h & 0xffn) << 8n) | (h >> 8n)) << BigInt(i);
            }
            break;
          }
          case 0x02: { // REV32
            r = 0n;
            for (let i = 0; i < bits; i += 32) {
              const q = (a >> BigInt(i)) & MASK32;
              r |= (((q & 0xffn) << 24n) | (((q >> 8n) & 0xffn) << 16n) |
                (((q >> 16n) & 0xffn) << 8n) | ((q >> 24n) & 0xffn)) << BigInt(i);
            }
            break;
          }
          case 0x03: { // REV
            r = 0n;
            for (let i = 0; i < bits; i += 8) r |= ((a >> BigInt(i)) & 0xffn) << BigInt(bits - 8 - i);
            break;
          }
          case 0x04: { // CLZ
            r = BigInt(bits - (a === 0n ? 0 : (a.toString(2).length)));
            break;
          }
          default: { // CLS
            const signed = BigInt.asIntN(bits, a);
            const abs = signed < 0n ? ~signed : signed;
            const lead = bits - (abs === 0n ? 0 : abs.toString(2).length);
            r = BigInt(lead - 1 < 0 ? 0 : lead - 1);
            break;
          }
        }
        this.wx(rd, r & M);
        return;
      }
      case C_DP2: {
        const sf = w >>> 31;
        const Rm = (w >>> 16) & 31;
        const opcode = (w >>> 10) & 0x3f;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const M = sf ? MASK64 : MASK32;
        const bits = sf ? 64 : 32;
        const a = this.rx(rn) & M;
        const b = this.rx(Rm) & M;
        let r: bigint;
        switch (opcode) {
          case 2: r = b === 0n ? 0n : a / b; break;
          case 3: {
            if (b === 0n) r = 0n;
            else {
              const sa = BigInt.asIntN(bits, a);
              const sb = BigInt.asIntN(bits, b);
              r = BigInt.asUintN(bits, sa / sb);
            }
            break;
          }
          case 8: r = this.shiftReg(a, 0, Number(b & BigInt(bits - 1)), sf); break;
          case 9: r = this.shiftReg(a, 1, Number(b & BigInt(bits - 1)), sf); break;
          case 10: r = this.shiftReg(a, 2, Number(b & BigInt(bits - 1)), sf); break;
          case 11: r = this.shiftReg(a, 3, Number(b & BigInt(bits - 1)), sf); break;
          default: throw new Error(`未知 dp2 opcode ${opcode}`);
        }
        this.wx(rd, r & M);
        return;
      }
      case C_DP3: {
        const sf = w >>> 31;
        const Rm = (w >>> 16) & 31;
        const op31 = (w >>> 21) & 7;
        const o0 = (w >>> 15) & 1;
        const Ra = (w >>> 10) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const a = this.rx(rn);
        const b = this.rx(Rm);
        const acc = this.rx(Ra);
        let r: bigint;
        if (op31 === 0) {
          const p = a * b;
          r = o0 === 1 ? acc - p : acc + p;
          r &= sf ? MASK64 : MASK32;
        } else if (op31 === 1) {
          const p = BigInt.asIntN(32, a) * BigInt.asIntN(32, b);
          r = (o0 === 1 ? acc - p : acc + p) & MASK64;
        } else if (op31 === 2) {
          r = (BigInt.asIntN(64, a) * BigInt.asIntN(64, b)) >> 64n;
          r &= MASK64;
        } else if (op31 === 5) {
          const p = (a & MASK32) * (b & MASK32);
          r = (o0 === 1 ? acc - p : acc + p) & MASK64;
        } else if (op31 === 6) {
          // UMULH：64×64 无符号乘积的高 64 位
          r = ((a & MASK64) * (b & MASK64)) >> 64n;
          r &= MASK64;
        } else throw new Error(`未知 dp3 op31 ${op31}`);
        this.wx(rd, r);
        return;
      }
      // ------------------------------------------------------------ 标量浮点
      case C_FMOV_IMM: {
        const type = (w >>> 22) & 3;
        const rd = w & 31;
        const bits = this.vfpExpand((w >>> 13) & 0xff, type === 0);
        this.setVlo(rd, bits);
        this.setVhi(rd, 0n);
        return;
      }
      case C_FMOV_WS: {
        const rn = (w >>> 5) & 31;
        this.wx(w & 31, this.vlo(rn) & MASK32);
        return;
      }
      case C_FMOV_XD: {
        const rn = (w >>> 5) & 31;
        this.wx(w & 31, this.vlo(rn));
        return;
      }
      case C_FMOV_SW: {
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        this.setVlo(rd, this.rx(rn) & MASK32);
        this.setVhi(rd, 0n);
        return;
      }
      case C_FMOV_DX: {
        const rn = (w >>> 5) & 31;
        this.setVlo(w & 31, this.rx(rn));
        this.setVhi(w & 31, 0n);
        return;
      }
      case C_FMOV_DD: {
        this.setVlo(w & 31, this.vlo((w >>> 5) & 31));
        this.setVhi(w & 31, 0n);
        return;
      }
      case C_FMOV_SS: {
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        this.setVlo(rd, this.vlo(rn) & MASK32);
        this.setVhi(rd, 0n);
        return;
      }
      case C_FABS_D: {
        const rn = (w >>> 5) & 31;
        this.setF64(w & 31, Math.abs(this.getF64(rn)));
        return;
      }
      case C_FABS_S: {
        const rn = (w >>> 5) & 31;
        this.setF32(w & 31, Math.abs(this.getF32(rn)));
        return;
      }
      case C_FNEG_D: {
        // 按位取反符号位，保证 NaN 也精确一致
        this.setVlo(w & 31, this.vlo((w >>> 5) & 31) ^ 0x8000000000000000n);
        this.setVhi(w & 31, 0n);
        return;
      }
      case C_FNEG_S: {
        const rn = (w >>> 5) & 31;
        this.setVlo(w & 31, (this.vlo(rn) & MASK32) ^ 0x80000000n);
        this.setVhi(w & 31, 0n);
        return;
      }
      case C_FSQRT_D: {
        this.setF64(w & 31, Math.sqrt(this.getF64((w >>> 5) & 31)));
        return;
      }
      case C_FSQRT_S: {
        this.setF32(w & 31, Math.sqrt(this.getF32((w >>> 5) & 31)));
        return;
      }
      case C_FABD_D: {
        const a = this.getF64((w >>> 5) & 31);
        const b = this.getF64((w >>> 16) & 31);
        this.setF64(w & 31, Math.abs(a - b));
        return;
      }
      case C_FABD_S: {
        const a = this.getF32((w >>> 5) & 31);
        const b = this.getF32((w >>> 16) & 31);
        this.setF32(w & 31, Math.abs(a - b));
        return;
      }
      case C_FMUL_D: {
        const a = this.getF64((w >>> 5) & 31);
        const b = this.getF64((w >>> 16) & 31);
        this.setF64(w & 31, a * b);
        return;
      }
      case C_FMUL_S: {
        const a = this.getF32((w >>> 5) & 31);
        const b = this.getF32((w >>> 16) & 31);
        this.setF32(w & 31, a * b);
        return;
      }
      case C_FADD_D: {
        const a = this.getF64((w >>> 5) & 31);
        const b = this.getF64((w >>> 16) & 31);
        this.setF64(w & 31, a + b);
        return;
      }
      case C_FADD_S: {
        const a = this.getF32((w >>> 5) & 31);
        const b = this.getF32((w >>> 16) & 31);
        this.setF32(w & 31, a + b);
        return;
      }
      case C_FSUB_D: {
        const a = this.getF64((w >>> 5) & 31);
        const b = this.getF64((w >>> 16) & 31);
        this.setF64(w & 31, a - b);
        return;
      }
      case C_FSUB_S: {
        const a = this.getF32((w >>> 5) & 31);
        const b = this.getF32((w >>> 16) & 31);
        this.setF32(w & 31, a - b);
        return;
      }
      case C_FDIV_D: {
        const a = this.getF64((w >>> 5) & 31);
        const b = this.getF64((w >>> 16) & 31);
        this.setF64(w & 31, a / b);
        return;
      }
      case C_FDIV_S: {
        const a = this.getF32((w >>> 5) & 31);
        const b = this.getF32((w >>> 16) & 31);
        this.setF32(w & 31, a / b);
        return;
      }
      case C_FMADD_D: {
        const n = this.getF64((w >>> 5) & 31);
        const m = this.getF64((w >>> 16) & 31);
        const a = this.getF64((w >>> 10) & 31);
        this.setF64(w & 31, n * m + a);
        return;
      }
      case C_FMADD_S: {
        const n = this.getF32((w >>> 5) & 31);
        const m = this.getF32((w >>> 16) & 31);
        const a = this.getF32((w >>> 10) & 31);
        this.setF32(w & 31, n * m + a);
        return;
      }
      case C_FMSUB_D: {
        const n = this.getF64((w >>> 5) & 31);
        const m = this.getF64((w >>> 16) & 31);
        const a = this.getF64((w >>> 10) & 31);
        this.setF64(w & 31, a - n * m);
        return;
      }
      case C_FMSUB_S: {
        const n = this.getF32((w >>> 5) & 31);
        const m = this.getF32((w >>> 16) & 31);
        const a = this.getF32((w >>> 10) & 31);
        this.setF32(w & 31, a - n * m);
        return;
      }
      case C_FNMADD_D: {
        const n = this.getF64((w >>> 5) & 31);
        const m = this.getF64((w >>> 16) & 31);
        const a = this.getF64((w >>> 10) & 31);
        this.setF64(w & 31, -a - n * m);
        return;
      }
      case C_FNMADD_S: {
        const n = this.getF32((w >>> 5) & 31);
        const m = this.getF32((w >>> 16) & 31);
        const a = this.getF32((w >>> 10) & 31);
        this.setF32(w & 31, -a - n * m);
        return;
      }
      case C_FNMSUB_D: {
        const n = this.getF64((w >>> 5) & 31);
        const m = this.getF64((w >>> 16) & 31);
        const a = this.getF64((w >>> 10) & 31);
        this.setF64(w & 31, n * m - a);
        return;
      }
      case C_FNMSUB_S: {
        const n = this.getF32((w >>> 5) & 31);
        const m = this.getF32((w >>> 16) & 31);
        const a = this.getF32((w >>> 10) & 31);
        this.setF32(w & 31, n * m - a);
        return;
      }
      case C_FCMP_D: {
        this.fpCompare(this.getF64((w >>> 5) & 31), this.getF64((w >>> 16) & 31));
        return;
      }
      case C_FCMP_S: {
        this.fpCompare(this.getF32((w >>> 5) & 31), this.getF32((w >>> 16) & 31));
        return;
      }
      case C_FCMP_D0: {
        this.fpCompare(this.getF64((w >>> 5) & 31), 0);
        return;
      }
      case C_FCMP_S0: {
        this.fpCompare(this.getF32((w >>> 5) & 31), 0);
        return;
      }
      case C_FCSEL_D: {
        const cond = (w >>> 12) & 0xf;
        const rn = (w >>> 5) & 31;
        const rm = (w >>> 16) & 31;
        this.setF64(w & 31, this.cond(cond) ? this.getF64(rn) : this.getF64(rm));
        return;
      }
      case C_FCSEL_S: {
        const cond = (w >>> 12) & 0xf;
        const rn = (w >>> 5) & 31;
        const rm = (w >>> 16) & 31;
        this.setF32(w & 31, this.cond(cond) ? this.getF32(rn) : this.getF32(rm));
        return;
      }
      case C_FCCMP_D: {
        const cond = (w >>> 12) & 0xf;
        if (this.cond(cond)) this.fpCompare(this.getF64((w >>> 5) & 31), this.getF64((w >>> 16) & 31));
        else this.nzcv = w & 0xf;
        return;
      }
      case C_FCCMP_S: {
        const cond = (w >>> 12) & 0xf;
        if (this.cond(cond)) this.fpCompare(this.getF32((w >>> 5) & 31), this.getF32((w >>> 16) & 31));
        else this.nzcv = w & 0xf;
        return;
      }
      case C_FCVTZS_WD: {
        const v = this.getF64((w >>> 5) & 31);
        let t = Math.trunc(v);
        if (!Number.isFinite(t)) t = v > 0 ? 2147483647 : v < 0 ? -2147483648 : 0;
        if (t > 2147483647) t = 2147483647;
        if (t < -2147483648) t = -2147483648;
        this.wx(w & 31, BigInt(t >>> 0));
        return;
      }
      case C_FCVTZS_XD: {
        const v = this.getF64((w >>> 5) & 31);
        let t = BigInt(Math.trunc(v));
        if (!Number.isFinite(v)) t = v > 0 ? 0x7fffffffffffffffn : -0x8000000000000000n;
        this.wx(w & 31, BigInt.asUintN(64, t));
        return;
      }
      case C_FCVTZU_WD: {
        const v = this.getF64((w >>> 5) & 31);
        let t = Math.trunc(v);
        if (!Number.isFinite(t)) t = v > 0 ? 4294967295 : 0;
        if (t > 4294967295) t = 4294967295;
        if (t < 0) t = 0;
        this.wx(w & 31, BigInt(t));
        return;
      }
      case C_FCVTZU_XD: {
        const v = this.getF64((w >>> 5) & 31);
        let t = Math.trunc(v);
        if (!Number.isFinite(t)) t = v > 0 ? 18446744073709551615 : 0;
        if (t < 0) t = 0;
        this.wx(w & 31, BigInt(t));
        return;
      }
      case C_FCVTPU_WS:
      case C_FCVTPU_WD:
      case C_FCVTPU_XS:
      case C_FCVTPU_XD: {
        // 向 +∞ 取整后转无符号整数，越界饱和
        const rn = (w >>> 5) & 31;
        const wide = c === C_FCVTPU_WD || c === C_FCVTPU_XD;
        const v = wide ? this.getF64(rn) : this.getF32(rn);
        const x = c === C_FCVTPU_XS || c === C_FCVTPU_XD;
        const t = Math.ceil(v);
        let big: bigint;
        if (!Number.isFinite(t)) big = v > 0 ? (x ? 0xffffffffffffffffn : 4294967295n) : 0n;
        else if (t < 0) big = 0n;
        else {
          big = x ? BigInt(t) : BigInt(Math.min(t, 4294967295));
          if (big > 0xffffffffffffffffn) big = 0xffffffffffffffffn;
        }
        this.wx(w & 31, big);
        return;
      }
      case C_SCVTF_DW:
      case C_UCVTF_DW: {
        const rn = (w >>> 5) & 31;
        const a = this.rx(rn) & MASK32;
        this.setF64(w & 31, c === C_SCVTF_DW ? Number(BigInt.asIntN(32, a)) : Number(a));
        return;
      }
      case C_SCVTF_DX:
      case C_UCVTF_DX: {
        const rn = (w >>> 5) & 31;
        const a = this.rx(rn);
        this.setF64(w & 31, c === C_SCVTF_DX ? Number(BigInt.asIntN(64, a)) : Number(a));
        return;
      }
      case C_SCVTF_DD:
      case C_UCVTF_DD: {
        const rn = (w >>> 5) & 31;
        const a = this.vlo(rn);
        this.setF64(w & 31, c === C_SCVTF_DD ? Number(BigInt.asIntN(64, a)) : Number(a));
        return;
      }
      case C_SCVTF_SS:
      case C_UCVTF_SS: {
        const rn = (w >>> 5) & 31;
        const a = this.vlo(rn) & MASK32;
        this.setF32(w & 31, c === C_SCVTF_SS ? Number(BigInt.asIntN(32, a)) : Number(a));
        return;
      }
      case C_SCVTF_SW:
      case C_UCVTF_SW: {
        const rn = (w >>> 5) & 31;
        const a = this.rx(rn) & MASK32;
        this.setF32(w & 31, c === C_SCVTF_SW ? Number(BigInt.asIntN(32, a)) : Number(a));
        return;
      }
      case C_SCVTF_SX:
      case C_UCVTF_SX: {
        const rn = (w >>> 5) & 31;
        const a = this.rx(rn);
        this.setF32(w & 31, c === C_SCVTF_SX ? Number(BigInt.asIntN(64, a)) : Number(a));
        return;
      }
      // ------------------------------------------------------------ SIMD
      case C_VEC_LOGIC: {
        const Q = (w >>> 30) & 1;
        const U = (w >>> 29) & 1;
        const size = (w >>> 22) & 3; // 与 U 一起决定逻辑运算种类
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const aLo = this.vlo(rn);
        const aHi = this.vhi(rn);
        const bLo = this.vlo(rm);
        const bHi = this.vhi(rm);
        const dLo = this.vlo(rd);
        const dHi = this.vhi(rd);
        const op = (U << 2) | size; // 0 AND 1 BIC 2 ORR 3 ORN 4 EOR 5 BSL 6 BIT 7 BIF
        let lo: bigint;
        let hi: bigint;
        switch (op) {
          case 0: lo = aLo & bLo; hi = aHi & bHi; break;
          case 1: lo = aLo & ~bLo; hi = aHi & ~bHi; break;
          case 2: lo = aLo | bLo; hi = aHi | bHi; break;
          case 3: lo = aLo | ~bLo; hi = aHi | ~bHi; break;
          case 4: lo = aLo ^ bLo; hi = aHi ^ bHi; break;
          case 5: // BSL：(Vn & Vm) | (~Vn & Vd)
          case 6: // BIT
            lo = (aLo & bLo) | (~aLo & dLo);
            hi = (aHi & bHi) | (~aHi & dHi);
            break;
          default: // BIF：(Vn & Vd) | (~Vn & Vm)
            lo = (aLo & dLo) | (~aLo & bLo);
            hi = (aHi & dHi) | (~aHi & bHi);
            break;
        }
        this.setVlo(rd, lo & MASK64);
        this.setVhi(rd, Q === 1 ? hi & MASK64 : 0n);
        return;
      }
      case C_VEC_ADD:
      case C_VEC_SUB: {
        const Q = (w >>> 30) & 1;
        const esize = 8 << ((w >>> 22) & 3);
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const mask = (1n << BigInt(esize)) - 1n;
        const sub = c === C_VEC_SUB;
        const calc = (a: bigint, b: bigint): bigint => {
          let out = 0n;
          for (let bit = 0; bit < 64; bit += esize) {
            const sh = BigInt(bit);
            const x = (a >> sh) & mask;
            const y = (b >> sh) & mask;
            out |= ((sub ? x - y : x + y) & mask) << sh;
          }
          return out;
        };
        this.setVlo(rd, calc(this.vlo(rn), this.vlo(rm)));
        this.setVhi(rd, Q === 1 ? calc(this.vhi(rn), this.vhi(rm)) : 0n);
        return;
      }
      case C_VEC_UMOV: {
        const Q = (w >>> 30) & 1;
        const { esize, index } = this.imm5ToLane((w >>> 16) & 0x1f);
        const val = this.getLane((w >>> 5) & 31, index, esize);
        this.wx(w & 31, Q === 1 ? val : val & MASK32);
        return;
      }
      case C_VEC_DUP_GEN: {
        const Q = (w >>> 30) & 1;
        const { esize } = this.imm5ToLane((w >>> 16) & 0x1f);
        const val = this.rx((w >>> 5) & 31) & ((1n << BigInt(esize)) - 1n);
        const rd = w & 31;
        const lanes = (Q === 1 ? 128 : 64) / esize;
        let lo = 0n;
        let hi = 0n;
        for (let i = 0; i < lanes; i++) {
          const bit = i * esize;
          if (bit < 64) lo |= val << BigInt(bit);
          else hi |= val << BigInt(bit - 64);
        }
        this.setVlo(rd, lo);
        this.setVhi(rd, hi);
        return;
      }
      case C_VEC_DUP_EL: {
        const Q = (w >>> 30) & 1;
        const { esize, index } = this.imm5ToLane((w >>> 16) & 0x1f);
        const val = this.getLane((w >>> 5) & 31, index, esize);
        const rd = w & 31;
        const lanes = (Q === 1 ? 128 : 64) / esize;
        let lo = 0n;
        let hi = 0n;
        for (let i = 0; i < lanes; i++) {
          const bit = i * esize;
          if (bit < 64) lo |= val << BigInt(bit);
          else hi |= val << BigInt(bit - 64);
        }
        this.setVlo(rd, lo);
        this.setVhi(rd, hi);
        return;
      }
      case C_VEC_MOVI: {
        const Q = (w >>> 30) & 1;
        const op = (w >>> 29) & 1;
        const cmode = (w >>> 12) & 0xf;
        const imm8 = (((w >>> 16) & 7) << 5) | ((w >>> 5) & 0x1f);
        const rd = w & 31;
        // (esize, shift)；cmode 与 op 的组合见 ARM ARM 的 AdvSIMD modified immediate 表
        const t = MOVI_LANES[cmode * 2 + op];
        if (t !== undefined) {
          const [esize, shift, msl, inv] = t;
          const mask = (1n << BigInt(esize)) - 1n;
          let v = (BigInt(imm8) << BigInt(shift)) | ((1n << BigInt(msl)) - 1n);
          if (inv === 1) v = ~v & mask;
          let lo = 0n;
          let hi = 0n;
          for (let bit = 0; bit < 64; bit += esize) {
            lo |= v << BigInt(bit);
            hi |= v << BigInt(bit);
          }
          this.setVlo(rd, lo);
          this.setVhi(rd, Q === 1 ? hi : 0n);
          return;
        }
        if (cmode === 0xf) {
          this.setVlo(rd, MASK64);
          this.setVhi(rd, Q === 1 ? MASK64 : 0n);
          return;
        }
        throw new Error(`未实现的 movi cmode=${cmode} op=${op}`);
      }
      case C_VEC_ZIP1:
      case C_VEC_UZP1: {
        const Q = (w >>> 30) & 1;
        const size = (w >>> 22) & 3;
        const esize = 8 << size;
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const lanes = (Q === 1 ? 128 : 64) / esize;
        const half = lanes / 2;
        const zip = c === C_VEC_ZIP1;
        // 先快照：rd 可能与 rn/rm 相同
        const as: bigint[] = [];
        const bs: bigint[] = [];
        for (let i = 0; i < lanes; i++) {
          as.push(this.getLane(rn, i, esize));
          bs.push(this.getLane(rm, i, esize));
        }
        for (let i = 0; i < half; i++) {
          if (zip) {
            // ZIP1：result[2i]=a[i], result[2i+1]=b[i]
            this.setLane(rd, 2 * i, esize, as[i]);
            this.setLane(rd, 2 * i + 1, esize, bs[i]);
          } else {
            // UZP1：result[i]=a[2i], result[half+i]=b[2i]
            this.setLane(rd, i, esize, as[2 * i]);
            this.setLane(rd, half + i, esize, bs[2 * i]);
          }
        }
        if (Q === 0) this.setVhi(rd, 0n);
        return;
      }
      case C_VEC_EXT: {
        const Q = (w >>> 30) & 1;
        const imm4 = (w >>> 11) & 0xf;
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const a = (this.vhi(rn) << 64n) | this.vlo(rn);
        const b = (this.vhi(rm) << 64n) | this.vlo(rm);
        const cat = (b << 128n) | a;
        const r = (cat >> BigInt(imm4 * 8)) & ((1n << 128n) - 1n);
        this.setVlo(rd, r & MASK64);
        this.setVhi(rd, Q === 1 ? (r >> 64n) & MASK64 : 0n);
        return;
      }
      case C_VEC_USHL: {
        const Q = (w >>> 30) & 1;
        const size = (w >>> 22) & 3;
        const esize = 8 << size;
        const rm = (w >>> 16) & 31;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const lanes = (Q === 1 ? 128 : 64) / esize;
        const mask = (1n << BigInt(esize)) - 1n;
        // 先快照：rd 可能与 rn/rm 相同
        const as: bigint[] = [];
        const bs: bigint[] = [];
        for (let i = 0; i < lanes; i++) {
          as.push(this.getLane(rn, i, esize));
          bs.push(this.getLane(rm, i, esize));
        }
        for (let i = 0; i < lanes; i++) {
          const a = as[i];
          // 移位量按有符号解释：负数即右移（USHL 逻辑右移 / SSHL 算术右移）
          const sh = BigInt.asIntN(esize, bs[i]);
          const lim = BigInt(esize);
          let r: bigint;
          if (sh >= lim || sh <= -lim) r = 0n;
          else if (sh >= 0n) r = (a << sh) & mask;
          else if (c === C_VEC_USHL) r = a >> -sh;
          else r = BigInt.asUintN(esize, BigInt.asIntN(esize, a) >> -sh);
          this.setLane(rd, i, esize, r);
        }
        if (Q === 0) this.setVhi(rd, 0n);
        return;
      }
      case C_VEC_SHL_SC: {
        const imm = (w >>> 16) & 0xff;
        if (imm === 0) throw new Error('非法 shl 立即数');
        // immh:immb 共 8 位，最高位位置决定 esize
        const size = 31 - Math.clz32(imm) - 3;
        const esize = 8 << size;
        const shift = imm - esize;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const mask = (1n << BigInt(esize)) - 1n;
        this.setLane(rd, 0, esize, (this.getLane(rn, 0, esize) << BigInt(shift)) & mask);
        this.setVhi(rd, 0n);
        return;
      }
      case C_VEC_SHL_V: {
        const Q = (w >>> 30) & 1;
        const imm = (w >>> 16) & 0xff;
        if (imm === 0) throw new Error('非法 shl 立即数');
        const size = 31 - Math.clz32(imm) - 3;
        const esize = 8 << size;
        const shift = BigInt(imm - esize);
        const lanes = (Q === 1 ? 128 : 64) / esize;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const mask = (1n << BigInt(esize)) - 1n;
        for (let i = 0; i < lanes; i++) {
          this.setLane(rd, i, esize, (this.getLane(rn, i, esize) << shift) & mask);
        }
        return;
      }
      case C_VEC_SSHLL: {
        const Q = (w >>> 30) & 1;
        const U = (w >>> 29) & 1;
        const immh = (w >>> 19) & 0xf;
        if (immh === 0) throw new Error('非法 sshll 立即数');
        const size = 31 - Math.clz32(immh);
        const esize = 8 << size;
        const shift = ((w >>> 16) & 0x7f) - (8 << size);
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        // 长指令：目的恒为 128 位；Q 只决定源取低 64 位还是高 64 位
        const lanes = 128 / (esize * 2);
        const srcBase = Q === 1 ? 64 / esize : 0;
        // 先快照源 lane：rd 可能与 rn 相同，边读边写会破坏后续源数据
        const vals: bigint[] = [];
        for (let i = 0; i < lanes; i++) vals.push(this.getLane(rn, srcBase + i, esize));
        for (let i = 0; i < lanes; i++) {
          const a = vals[i];
          const v = U === 1
            ? (a & ((1n << BigInt(esize)) - 1n))
            : BigInt.asUintN(esize * 2, BigInt.asIntN(esize, a));
          this.setLane(rd, i, esize * 2, v << BigInt(shift));
        }
        return;
      }
      case C_VEC_CNT: {
        const Q = (w >>> 30) & 1;
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const lanes = Q === 1 ? 16 : 8;
        let lo = 0n;
        let hi = 0n;
        for (let i = 0; i < lanes; i++) {
          let b = Number(this.getLane(rn, i, 8));
          let n = 0;
          while (b !== 0) {
            n += b & 1;
            b >>>= 1;
          }
          if (i < 8) lo |= BigInt(n) << BigInt(i * 8);
          else hi |= BigInt(n) << BigInt((i - 8) * 8);
        }
        this.setVlo(rd, lo);
        this.setVhi(rd, hi);
        return;
      }
      case C_VEC_UADDLV: {
        const Q = (w >>> 30) & 1;
        const U = (w >>> 29) & 1;
        const esize = 8 << ((w >>> 22) & 3);
        const rn = (w >>> 5) & 31;
        const rd = w & 31;
        const lanes = (Q === 1 ? 128 : 64) / esize;
        let sum = 0n;
        for (let i = 0; i < lanes; i++) {
          const e = this.getLane(rn, i, esize);
          sum += U === 1 ? e : BigInt.asIntN(esize, e);
        }
        this.setVlo(rd, sum & MASK64);
        this.setVhi(rd, 0n);
        return;
      }
      default:
        throw new Error(
          `未实现指令 0x${w.toString(16).padStart(8, '0')} (class=${c}) @0x${(this.pc - 4).toString(16)}`,
        );
    }
  }
}
