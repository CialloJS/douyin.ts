/**
 * 纯 TS 执行 libmetasec_ml.so 生成签名头（等价 unidbg_work/medusa_pure.py）。
 *
 * 只补「边界层」：JNI stub、libc/syscall、少量 unidbg 侧 hook（cntvct/时间/srand/keyfix）。
 * 中间 5 千万条 AArch64 指令全部由 src/arm64/cpu.ts 解释执行，不 spawn python/java。
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { Cpu } from './cpu.js';
import { applyRelocs, ElfImage, mapImage, readInitArray } from './elf.js';
import { Jit } from './jit.js';
import { PageMem } from './mem.js';
import { ALLOC_REPLAY } from './alloc.js';

export const SO_BASE = 0x40000000;
export const FROZEN_TS = 1794343920;
const FROZEN_SUB = 0;
const MONO_BASE_US = 1000000;
const MONO_STEP_US = 1000;
const PID = 12345;
/** so+0x280a34（fread 返回点）回填 so+0x467310 的 16 字节 UUID 种子 */
const KEYFIX = Buffer.from('00112233445566778899aabbccddeeff', 'hex');

/** i3.java 初始化配置里的 license（与 MsSign.java 的 LICENSE 常量一致） */
const LICENSE =
  'bo95dJizD1WFcV03zOuLzN5Pn1sFtVa3szqiVQmflMJTNW0p0Kpqfw8D4i0zUlfrou4kuYt/i0521YRygM83dwv/wn3DD+TMJF+QFzW9wb8Qq2/1B4jPMbObrDNdyMMukpAYqy1fLWtbLGVIPxsFsZegwQy5lsRX9h49PH/Qx8MwgYvWvH7ZTFLV28LwTWZiljQyBPaBE+TsyumEu0Y+JRkeidHFEYcVs0yRoa+xC004hugQhdPupIt6dBiWA4phsB3fNJZjFTAKGE1lPB4gzt6Qf+FmlgZBbRvT8zekxTV2HZ5dUvSutB2/0QpbHKAvWL4DRA==';

export type ObjKind =
  | 'string' | 'bytearray' | 'objarray' | 'boolean' | 'long' | 'object' | 'class'
  | 'map' | 'set' | 'iter' | 'entry' | 'json';

export interface Obj {
  kind: ObjKind;
  val: unknown;
}

/** unidbg 生成的 jmethodID（跨运行稳定），用于识别落盘前已缓存在 so 内存里的方法 */
const KNOWN_METHODS = new Map<number, [string, string, string, string]>([
  [0x318b4ca9, ['java/lang/String', 'getBytes', '(Ljava/lang/String;)[B', 'L']],
  [0x8ef8fc19, ['android/app/Application', 'getPackageName', '()Ljava/lang/String;', '']],
  [0x2f94ee13, ['com/bytedance/mobsec/metasec/ml/MS', 'b', '(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;', 'IIJLL']],
  [0x1d8c249f, ['java/lang/Boolean', 'valueOf', '(Z)Ljava/lang/Boolean;', 'Z']],
  [0x1a324bff, ['java/lang/Long', 'valueOf', '(J)Ljava/lang/Long;', 'J']],
  [0x4bfa55cc, ['com/bytedance/mobsec/metasec/ml/MS', 'a', '()V', '']],
]);

/** 「调用点 → JNI 语义」真值表（来自 unidbg 运行时日志 postjni2.txt） */
const SITE_SEM = new Map<number, string>([
  [0x29cc04, 'NewStringUTF'],
  [0x29ce90, 'NewStringUTF'],
  [0x29c518, 'GetMethodID'],
  [0x227d00, 'GetStaticMethodID'],
  [0x29c620, 'CallObjectMethodV'],
  [0x29c5f0, 'CallObjectMethodV'],
  [0x29cda4, 'GetArrayLength'],
  [0x29cde4, 'GetByteArrayRegion'],
  [0x29b5ec, 'CallStaticObjectMethodV'],
  [0x29e25c, 'NewObjectArray'],
  [0x29e2f8, 'SetObjectArrayElement'],
  [0x29e314, 'SetObjectArrayElement'],
  [0x29c4f0, 'ExceptionCheck'],
  [0x29c4dc, 'GetObjectClass'],
]);

/** JavaVM 调用点 */
const VM_SITE = new Map<number, string>([
  [0x29bd64, 'VM_GetEnv'],
  [0x29bc88, 'VM_Attach'],
  [0x29bba8, 'VM_Detach'],
]);

/** JavaVM 表下标兜底（4=Attach 5=Detach 6=GetEnv 7=AttachAsDaemon） */
const VM_IDX_SEM = new Map<number, string>([
  [1004, 'VM_Attach'], [1005, 'VM_Detach'], [1006, 'VM_GetEnv'], [1007, 'VM_Attach'],
]);

/** 兜底：按 JNI 表下标（快照内存实测的语义） */
const IDX_SEM = new Map<number, string>([
  [167, 'NewStringUTF'], [33, 'GetMethodID'], [113, 'GetStaticMethodID'],
  [53, 'CallObjectMethodV'], [171, 'GetArrayLength'], [200, 'GetByteArrayRegion'],
  [115, 'CallStaticObjectMethodV'], [172, 'NewObjectArray'],
  [174, 'SetObjectArrayElement'], [228, 'ExceptionCheck'], [31, 'GetObjectClass'],
  [26, 'EnsureLocalCapacity'], [232, 'GetObjectRefType'],
  [21, 'NewGlobalRef'], [22, 'DeleteGlobalRef'], [23, 'DeleteLocalRef'],
  [19, 'PushLocalFrame'], [20, 'PopLocalFrame'], [17, 'ExceptionOccurred'],
  [6, 'FindClass'], [4, 'GetVersion'], [215, 'RegisterNatives'], [10, 'GetSuperclass'],
  [176, 'NewByteArray'], [184, 'GetByteArrayElements'], [192, 'ReleaseByteArrayElements'],
  [208, 'SetByteArrayRegion'], [35, 'CallObjectMethodV'],
  [169, 'GetStringUTFChars'], [170, 'ReleaseStringUTFChars'],
  [38, 'CallBooleanMethodV'], [50, 'CallIntMethodV'], [62, 'CallVoidMethodV'],
]);

/** unidbg VaList64 的等价实现 */
class VaList {
  private stack: number;
  private grTop: number;
  private vrTop: number;
  private grOffs: number;
  private vrOffs: number;
  private i = 0;

  constructor(
    private readonly mem: PageMem,
    p: number,
    private readonly shorty: string,
  ) {
    this.stack = Number(mem.read(p, 8));
    this.grTop = Number(mem.read(p + 8, 8));
    this.vrTop = Number(mem.read(p + 16, 8));
    this.grOffs = s32(Number(mem.read(p + 24, 4)));
    this.vrOffs = s32(Number(mem.read(p + 28, 4)));
  }

  private gprAddr(): number {
    if (this.grOffs & -0x80000000) {
      if (this.grOffs + 8 <= 0) {
        const a = this.grTop + this.grOffs;
        this.grOffs += 8;
        return a;
      }
      const a = this.stack;
      this.grOffs += 8;
      this.stack = (this.stack + 11) & ~7;
      return a;
    }
    const a = this.stack;
    this.stack = (this.stack + 11) & ~7;
    return a;
  }

  private vrAddr(): number {
    if (this.vrOffs & -0x80000000) {
      if (this.vrOffs + 16 <= 0) {
        const a = this.vrTop + this.vrOffs;
        this.vrOffs += 16;
        return a;
      }
      const a = this.stack;
      this.vrOffs += 16;
      this.stack = (this.stack + 15) & ~7;
      return a;
    }
    const a = this.stack;
    this.stack = (this.stack + 15) & ~7;
    return a;
  }

  next(): number {
    const t = this.shorty[this.i];
    this.i += 1;
    if (t === 'J') return Number(this.mem.read(this.gprAddr(), 8));
    if ('BCISZL'.includes(t)) return Number(this.mem.read(this.gprAddr(), 4));
    if ('DF'.includes(t)) return Number(this.mem.read(this.vrAddr(), 8));
    throw new Error(`va_list: unsupported shorty ${t}`);
  }

  /** 取下一个整数参数（printf 用；size=4/8） */
  int(size: number): number {
    return Number(this.mem.read(this.gprAddr(), size));
  }

  /** 取下一个双精度参数（printf 的 %f 等） */
  fp(): number {
    const dv = new DataView(new ArrayBuffer(8));
    dv.setBigUint64(0, this.mem.read(this.vrAddr(), 8), true);
    return dv.getFloat64(0, true);
  }
}

/** printf 类函数的取参抽象（va_list 或寄存器） */
interface ArgSrc {
  int(size: number): number;
  fp(): number;
}

function s32(v: number): number {
  v &= 0xffffffff;
  return v & 0x80000000 ? v - 0x100000000 : v;
}

/** 按 JNI 签名求 shorty（L 开头/数组都算 L） */
function shorty(sig: string): string {
  const out: string[] = [];
  let i = 1;
  while (i < sig.length && sig[i] !== ')') {
    const c = sig[i];
    if (c === 'L') {
      i = sig.indexOf(';', i) + 1;
      out.push('L');
      continue;
    }
    if (c === '[') {
      out.push('L');
      while (sig[i] === '[') i += 1;
      if (sig[i] === 'L') i = sig.indexOf(';', i) + 1;
      else i += 1;
      continue;
    }
    out.push(c);
    i += 1;
  }
  return out.join('');
}

/** so+0x2aa800 的 8 字节混合（X-Medusa 明文 fl 的第 4 个字段） */
function flHash(v: number): number {
  let w9 = 0x201507;
  const st = new Uint8Array(8);
  new DataView(st.buffer).setUint32(0, v >>> 0, true);
  for (let i = 0; i < 8; i++) {
    const b = st[i];
    if (i % 2 === 0) {
      w9 = ((w9 ^ (w9 << 6)) ^ (w9 >>> 4)) >>> 0;
      w9 = (w9 ^ b) >>> 0;
    } else {
      const w11 = ((b & ~(0xfffff << 12)) | ((w9 & 0xfffff) << 12)) >>> 0;
      w9 = (w9 ^ (w9 >>> 7)) >>> 0;
      w9 = (~(w9 ^ w11)) >>> 0;
    }
  }
  return w9;
}

/** 冷启动：直接加载 .so + 系统库，不读 state_a 快照 */
export interface ColdOptions {
  /** libmetasec_ml.so 路径 */
  soPath: string;
  /** 含 libc.so / libdl.so / libm.so / liblog.so 的目录（Android sdk23 arm64） */
  libDir: string;
  /** setDeviceID 的入参 */
  deviceId?: string;
  /** setInstallID 的入参 */
  installId?: string;
  /** 调试：在最终签名调用入口把 so/libc/栈 dump 到该目录（与 state_a 对拍用） */
  dumpDir?: string;
}

export interface SoSignOptions {
  /** state_a 快照目录（快照模式必填） */
  stateDir?: string;
  /** 冷启动配置（给了就忽略 stateDir） */
  cold?: ColdOptions;
  /** 参与签名的 URL */
  url: string;
  /** POST body（String 形态，utf8 后与 bodyBytes 等价） */
  body?: string;
  /** POST body（byte[] 形态，二进制密文用这个） */
  bodyBytes?: Uint8Array;
  ts?: number;
  pid?: number;
  srand?: number;
  keyfix?: Uint8Array;
  verbose?: boolean;
  /** 打印前 N 条指令（调试用） */
  trace?: number;
  /** 打印最后 N 条指令（调试用） */
  tail?: number;
  /** 记录前 N 条指令的 pc 序列（调试用，供与 Python oracle 逐条比对） */
  tracePc?: number;
  /** 命中该 so 内偏移时 dump 全部寄存器（调试用） */
  regPc?: number;
  /** 写监视 [地址, 长度]（调试用） */
  watch?: [number, number];
  /** 命中第 N 条指令时 dump 寄存器并停止（调试用） */
  stepDump?: number;
  maxSteps?: number;
}

export interface SoSignResult {
  /** 从返回的对象数组里解出的头（如 X-Medusa） */
  headers: Record<string, string>;
  stopReason: string;
  steps: number;
  jniCalls: Record<string, number>;
  syscalls: number[];
  newStrings: string[];
  /** 返回的原始对象（调试用） */
  retObj: Obj | undefined;
}

export class SoSigner {
  private readonly mem = new PageMem();
  private cpu!: Cpu;
  private segs: [number, number][] = [];
  private regs: Record<string, number> = {};
  /** 快照寄存器原值：64 位十六进制串直接转 BigInt，避免 Number 丢精度（x29/x1 常超 2^53） */
  private readonly regs64 = new Map<string, bigint>();
  private base = SO_BASE;
  private ts: number;
  private pid: number;
  private srand: number | null;
  private keyfix: Uint8Array;
  private verbose: boolean;
  private trace: number;
  private tailN: number;
  private tracePc: number;
  private regPc: number;
  private watchSpec?: [number, number];
  private ctxTrace: string[] = [];
  /** 基本块级对拍（SO_BBLOG）：是否在记录、上一条 pc、块首序列 */
  private bbActive = false;
  private bbPrev = -1;
  private bbBlocks: number[] = [];
  private bbReads: string[] = [];
  private bbWrites: string[] = [];
  /** SO_RFLOG：VM regfile 写入序列 */
  private rfLog: string[] = [];
  /** SO_RFLOG 门控：memset(0x40ad4380, 0, 0x2e3) 之后开始记录 */
  private rfOn = false;
  /** SO_WLOG：指定区间的写入序列（含 libc stub 的 C/F 记录） */
  private wlog: string[] = [];
  /** SO_LDRBLOG：VM ldrb（0x189a98）读取序列 */
  private ldrbLog: string[] = [];
  private stepDump: number;
  private readonly tailBuf: string[] = [];
  private maxSteps: number;
  /** 块级 JIT（无调试开关时启用） */
  private jit: Jit | null = null;
  /** 建 JIT 时的 pcHooks 数量（变了就重建，避免漏掉新装的钩子） */
  private jitHooks = -1;
  /** 块被遇到多少次才编译（SO_JITTHRESH 可覆盖，调优用） */
  private readonly jitThresh = Number(process.env.SO_JITTHRESH ?? 64) || 64;

  // ---- 冷启动模式（不读快照） ----
  private readonly coldLibs: { name: string; img: ElfImage; base: number }[] = [];
  private coldMeta!: ElfImage;
  private readonly coldGlobals = new Map<string, number>();
  private readonly coldNative = new Map<string, number>();
  /** GetByteArrayElements 借出的线性内存（0x30000000 起每块 64KB） */
  private arrMem = 0x30000000;
  /** 借出指针 → 对应 jarray 句柄，Release 时按 mode 拷回 */
  private readonly arrPtr = new Map<number, number>();
  private coldInitArray: number[] = [];
  private coldJniOnLoad = 0;
  private coldStarted = false;
  private coldEnv = 0xfffe1300;
  private coldVm = 0xfffe1310;
  private coldSentinel = 0x0c0;
  private coldSp = Number(process.env.SO_SP ?? 0xbffff700);
  private mmapNext = 0x41000000;
  private coldClassHandle = 0x6a000001;
  private coldApplication = 0x6a000002;
  private coldEntry = 0;
  private readonly coldUnknown = new Set<number>();
  /** 最近 512 条指令 pc 的环形缓冲（仅用于异常诊断） */
  private readonly coldTail: number[] = new Array(512).fill(0);
  private coldTailIdx = 0;
  private coldInLibc = false;
  /** 冷启动的 bump 分配器（libc 的 dlmalloc 会走 SIMD，只能自己实现） */
  private coldHeap = Number(process.env.SO_HEAP_BASE ?? 0x52000000);
  private readonly coldAllocs = new Map<number, number>();
  /** 签名阶段按 oracle 的 dlmalloc 序列回放堆地址 */
  private replayOn = false;
  private replayIdx = 0;
  private replayList: { name: string; n: number; addr: number }[] = [];
  private coldKeySeq = 1;
  private readonly coldTls = new Map<number, number>();
  private coldDepth = 0;
  /** 假 FILE* → fd */
  private readonly coldFiles = new Map<number, number>();

  private urlHandle = 0;
  private entryPc = 0;
  private retPc = 0;

  private readonly objs = new Map<number, Obj>();
  private nextHandle = 0x70000000;
  private readonly methods = new Map<number, [string, string, string, string]>(KNOWN_METHODS);
  private readonly midOf = new Map<string, number>();
  private readonly classes = new Map<number, string>();
  private readonly fds = new Map<number, { kind: string; data: Uint8Array | null }>();
  private nextFd = 3;
  private tick = 0x100000;
  private monoUs = -1;
  /** 只跑初始化（warmUp）：停在 getFeatureHash 入口前 */
  private warmOnly = false;
  /** 预热基线：init 完成时的内存页与对象句柄状态，signFast 每次恢复它 */
  private baseline: {
    pages: Map<number, Uint8Array>;
    objs: Map<number, Obj>;
    handle2: number;
    urlHandle: number;
    nextHandle: number;
    mmapNext: number;
    heap: number;
    monoUs: number;
  } | null = null;

  private readonly imm2jni = new Map<number, number>();
  private readonly jni2imm = new Map<number, number>();
  /** 返回值 true 表示已模拟完整条指令（pc 已推进），false 表示只改了现场、仍需执行该指令 */
  private readonly pcHooks = new Map<number, (cpu: Cpu) => boolean>();

  readonly jniCount: Record<string, number> = {};
  readonly svcLog: number[] = [];
  readonly nstr: string[] = [];
  /** tracePc 打开时记录的 pc 序列 */
  readonly pcSeq: number[] = [];

  private stopReason = '';
  private donePc: number | null = null;
  private steps = 0;
  /** 与 Python oracle 对齐的指令序号（pcHook 命中也计数） */
  private pcIndex = 0;

  constructor(private readonly opts: SoSignOptions) {
    this.ts = opts.ts ?? FROZEN_TS;
    this.pid = opts.pid ?? PID;
    this.srand = opts.srand ?? (process.env.DY_SRAND ? Number(process.env.DY_SRAND) : null);
    this.keyfix = opts.keyfix ?? KEYFIX;
    this.verbose = opts.verbose ?? false;
    this.trace = opts.trace ?? 0;
    this.tailN = opts.tail ?? 0;
    this.tracePc = opts.tracePc ?? 0;
    this.regPc = opts.regPc ?? 0;
    this.watchSpec = opts.watch;
    this.stepDump = opts.stepDump ?? 0;
    this.maxSteps = opts.maxSteps ?? 200_000_000;
    for (const [mid, v] of KNOWN_METHODS) this.midOf.set(`${v[0]}\u0000${v[1]}\u0000${v[2]}`, mid);
  }

  // ---------------------------------------------------------------- 载入

  private load(): void {
    const dir = this.opts.stateDir ?? '';
    const files = new Map<number, string>();
    for (const line of readFileSync(join(dir, 'memmap.txt'), 'utf8').split(/\r?\n/)) {
      const t = line.trim();
      if (!t) continue;
      const [name, b, s] = t.split(/\s+/);
      const base = parseInt(b, 16);
      this.segs.push([base, parseInt(s, 16)]);
      files.set(base, name);
    }
    for (const [b, s] of this.segs) this.mem.map(b, (s + 0xfff) & ~0xfff);
    for (const [b, name] of files) this.mem.load(b, readFileSync(join(dir, name)));
    for (const line of readFileSync(join(dir, 'regs.txt'), 'utf8').split(/\r?\n/)) {
      const p = line.trim().split(/\s+/);
      if (p.length === 2) {
        const v = BigInt(`0x${p[1]}`);
        this.regs64.set(p[0], v);
        this.regs[p[0]] = Number(v);
      }
    }
    this.urlHandle = this.regs.x5;
    this.base = this.regs.base ?? SO_BASE;
    this.objs.set(this.urlHandle, { kind: 'string', val: this.opts.url });
    // POST body：快照里 x6 是 jobject body（null 时是 0），换成我们的句柄
    if (this.opts.bodyBytes) {
      this.regs64.set('x6', BigInt(this.newHandle({ kind: 'bytearray', val: this.opts.bodyBytes })));
    } else if (this.opts.body) {
      this.regs64.set('x6', BigInt(this.newHandle({ kind: 'string', val: this.opts.body })));
    }
    this.objs.set(0x2177849e, { kind: 'object', val: 'application' });
    this.cpu = new Cpu(this.mem);
    if (this.watchSpec) {
      const [lo, len] = this.watchSpec;
      this.mem.watch = {
        lo,
        hi: lo + len,
        cb: (a, s, v) => console.log(`[memwr] #${this.steps} pc=+0x${(this.cpu.pc - this.base).toString(16)} ` +
          `addr=0x${a.toString(16)} size=${s} v=0x${v.toString(16)}`),
      };
    }
  }

  private valid(addr: number, n = 1): boolean {
    for (const [b, s] of this.segs) if (b <= addr && addr + n <= b + s) return true;
    return false;
  }

  private setRegs(): void {
    const cpu = this.cpu;
    const g = (k: string): bigint => this.regs64.get(k) ?? 0n;
    for (let i = 0; i < 29; i++) cpu.x[i] = g(`x${i}`);
    cpu.x[29] = g('x29');
    cpu.x[30] = g('x30');
    cpu.x[31] = g('sp');
    cpu.pc = Number(g('pc'));
    cpu.tpidr = g('tpidr');
    this.entryPc = cpu.pc;
    this.retPc = Number(cpu.x[30]);
  }

  /** so 在 init_array 里把冻结毫秒缓存进若干全局，X-Medusa 的「距初始化耗时」取的就是它 */
  private patchInitTime(): void {
    const ms = this.ts * 1000 + Math.floor(FROZEN_SUB / 1000);
    const spec = ['469b98', '798020', 'ac2050', 'ad1008', 'ad12b0', '797118'];
    for (const a of spec) {
      if (a === '797118') this.mem.write(this.base + 0x797118, 4, BigInt(this.ts));
      else this.mem.write(this.base + parseInt(a, 16), 8, BigInt(ms));
    }
    const ms64 = BigInt(ms);
    const f2 = Number((ms64 & 0xffffffffn) ^ ((ms64 >> 32n) & 0xffffffffn)) >>> 0;
    const f3 = (((f2 & 0xff) << 24) | ((f2 & 0xff00) << 8) | ((f2 >>> 8) & 0xff00) | (f2 >>> 24)) >>> 0;
    const f4 = flHash(f3);
    this.mem.write(this.base + 0x459ea0, 4, BigInt(f2));
    this.mem.write(this.base + 0x459ea4, 4, BigInt(f3));
    this.mem.write(this.base + 0x459ea8, 4, BigInt(f4));
  }

  /** 从 JNIEnv 表里解出每个 stub 的 svc imm（imm → 表下标） */
  private decodeJniTable(): void {
    const env = this.regs.x0;
    let tbl: number;
    try {
      tbl = Number(this.mem.read(env, 8));
    } catch {
      return;
    }
    if (this.verbose) console.log(`[jni] JNIEnv=0x${env.toString(16)} table=0x${tbl.toString(16)}`);
    for (let i = 0; i < 260; i++) {
      let p: number;
      try {
        p = Number(this.mem.read(tbl + 8 * i, 8));
      } catch {
        break;
      }
      if (!this.valid(p, 4)) continue;
      const w = this.mem.fetch(p);
      if (((w & 0xffe0001f) >>> 0) === 0xd4000001) {
        const imm = (w >>> 5) & 0xffff;
        this.imm2jni.set(imm, i);
        this.jni2imm.set(i, imm);
      }
    }
    if (this.verbose) {
      const list = [...this.imm2jni.entries()].sort((a, b) => a[1] - b[1]);
      console.log('[jni] stubs: ' + list.map(([imm, i]) => `${i}->0x${imm.toString(16)}`).join(', '));
    }
  }

  // ---------------------------------------------------------------- pc 钩子

  private installHooks(): void {
    // cntvct 固定（unidbg installCntvctFix 的 8 个站点）
    for (const off of [0x21249c, 0x2124b4, 0x212514, 0x21252c,
      0x21258c, 0x2125a4, 0x2125f4, 0x21260c]) {
      this.pcHooks.set(this.base + off, (cpu) => {
        cpu.x[10] = BigInt(this.tick);
        cpu.x[11] = BigInt(this.tick);
        this.tick += 1000;
        cpu.pc = this.base + off + 4;
        return true;
      });
    }
    // libc 时间函数：直接返回冻结时间
    this.pcHooks.set(0x40603ae4, (cpu) => {
      const lr = Number(cpu.x[30]);
      const a0 = Number(cpu.x[0]);
      if (a0) this.mem.write(a0, 8, BigInt(this.ts));
      cpu.x[0] = BigInt(this.ts);
      cpu.pc = lr;
      return true;
    });
    this.pcHooks.set(0x405cd854, (cpu) => {
      const lr = Number(cpu.x[30]);
      const clk = Number(cpu.x[0]);
      const tp = Number(cpu.x[1]);
      const [sec, nsec] = clk === 0 || clk === 5 ? [this.ts, FROZEN_SUB] : this.monoTime();
      if (tp) {
        this.mem.write(tp, 8, BigInt(sec));
        this.mem.write(tp + 8, 8, BigInt(nsec));
      }
      cpu.x[0] = 0n;
      cpu.pc = lr;
      return true;
    });
    this.pcHooks.set(0x405cd8e4, (cpu) => {
      const lr = Number(cpu.x[30]);
      const tv = Number(cpu.x[0]);
      if (tv) {
        this.mem.write(tv, 8, BigInt(this.ts));
        this.mem.write(tv + 8, 8, BigInt(FROZEN_SUB));
      }
      cpu.x[0] = 0n;
      cpu.pc = lr;
      return true;
    });
    // srand 调用点：默认**不改**种子，让 so 用自己读到的当前时间播种
    // （x-helios 的 rand1 就是这里的 rand()，改死种子会让每个请求的 rand1 恒等，
    //   风控判为重放 → passport 侧 error_code=7）；opts.srand / DY_SRAND 仅调试用。
    this.pcHooks.set(this.base + 0x299914, (cpu) => {
      if (this.srand === null) {
        if (this.verbose) console.log(`[srand] seed = 0x${Number(cpu.x[0]).toString(16)}（沿用 so 自己算的）`);
        return false;
      }
      if (this.verbose) console.log(`[srand] seed -> 0x${this.srand.toString(16)} @+0x299914`);
      cpu.x[0] = BigInt(this.srand);
      return false;
    });
    // /dev/urandom 种子回填（只写内存，仍需执行该指令）
    this.pcHooks.set(this.base + 0x280a34, () => {
      if (this.verbose) console.log('[keyfix] so+0x467310 <- ' + Buffer.from(this.keyfix).toString('hex'));
      this.mem.load(this.base + 0x467310, this.keyfix);
      return false;
    });
  }

  private monoTime(): [number, number] {
    if (this.monoUs < 0) this.monoUs = MONO_BASE_US;
    else this.monoUs += MONO_STEP_US;
    return [Math.floor(this.monoUs / 1000000), (this.monoUs % 1000000) * 1000];
  }

  // ---------------------------------------------------------------- 对象

  private newHandle(obj: Obj): number {
    const h = this.nextHandle;
    this.nextHandle += 0x10;
    this.objs.set(h, obj);
    return h;
  }

  private obj(h: number): Obj | undefined {
    return this.objs.get(h);
  }

  private ret(cpu: Cpu, val: number | bigint): void {
    cpu.x[0] = BigInt.asUintN(64, BigInt(val));
    cpu.pc = Number(cpu.x[30]);
  }

  // ---------------------------------------------------------------- svc 分发

  private onSvc(cpu: Cpu, imm: number): void {
    if (imm >= 0x100) {
      this.doJni(cpu, imm);
    } else if (imm === 0) {
      this.doSyscall(cpu, Number(cpu.x[8]));
    } else {
      this.doSyscall(cpu, imm);
    }
  }

  private doJni(cpu: Cpu, imm: number): void {
    const idx = this.imm2jni.get(imm);
    const x1 = Number(cpu.x[1]);
    const x2 = Number(cpu.x[2]);
    const x3 = Number(cpu.x[3]);
    const x4 = Number(cpu.x[4]);
    const lr = Number(cpu.x[30]);
    const off = lr - this.base;
    const sem = SITE_SEM.get(off) ?? VM_SITE.get(off) ??
      (idx !== undefined ? (idx >= 1000 ? VM_IDX_SEM.get(idx) : IDX_SEM.get(idx)) : undefined);
    const key = sem ?? '?';
    this.jniCount[key] = (this.jniCount[key] ?? 0) + 1;
    if (this.verbose) console.log(`[jni] +0x${off.toString(16)} ${key} (idx=${idx} imm=0x${imm.toString(16)})`);

    if (sem === 'VM_GetEnv' || sem === 'VM_Attach') {
      if (x1) this.mem.write(x1, 8, BigInt(this.envPtr()));
      if (this.verbose) console.log(`[vm] ${sem} -> env=0x${this.envPtr().toString(16)}`);
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'VM_Detach') {
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'NewStringUTF') {
      const txt = this.mem.cstr(x1);
      this.nstr.push(txt);
      if (process.env.SO_NSTRADDR) {
        writeFileSync('d:/there/douyinhook/unidbg_work/nstrlog.txt',
          `0x${x1.toString(16)} len=${txt.length}\t${txt.length <= 60 ? txt : txt.slice(0, 60) + '...'}\n`,
          { flag: 'a' });
      }
      if (this.verbose) console.log(`[nstr] ${JSON.stringify(txt.length <= 80 ? txt : txt.slice(0, 80) + '...')}`);
      this.ret(cpu, this.newHandle({ kind: 'string', val: txt }));
      return;
    }
    if (sem === 'GetStringUTFChars') {
      const o = this.obj(x1);
      const buf = Buffer.from(`${o && o.kind === 'string' ? (o.val as string) : ''}\0`, 'utf8');
      const p = this.arrMem;
      this.arrMem += 0x10000;
      this.mem.map(p, Math.max(1, buf.length));
      this.mem.load(p, new Uint8Array(buf));
      if (x2) this.mem.write(x2, 4, 1n);
      this.ret(cpu, p);
      return;
    }
    if (sem === 'ReleaseStringUTFChars') {
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'GetMethodID' || sem === 'GetStaticMethodID') {
      const name = this.mem.cstr(x2);
      const sig = this.mem.cstr(x3);
      const cls = this.classes.get(x1);
      let mid = cls !== undefined ? this.midOf.get(`${cls}\u0000${name}\u0000${sig}`) : undefined;
      if (mid === undefined) {
        for (const [m2, v] of this.methods) {
          if (v[1] === name && v[2] === sig) {
            mid = m2;
            break;
          }
        }
      }
      if (mid === undefined) {
        mid = this.nextHandle;
        this.nextHandle += 0x10;
      }
      const c = cls ?? '?';
      this.methods.set(mid, [c, name, sig, shorty(sig)]);
      this.midOf.set(`${cls ?? '?'}\u0000${name}\u0000${sig}`, mid);
      if (this.verbose) console.log(`[mid] ${cls ?? '0x' + x1.toString(16)}.${name}${sig} => 0x${mid.toString(16)}`);
      this.ret(cpu, mid);
      return;
    }
    if (sem === 'CallObjectMethodV') {
      const o = this.obj(x1);
      const info = this.methods.get(x2);
      const name = info ? info[1] : '?';
      if (this.verbose) console.log(`[call] ${name}(${o ? o.kind : 'null'})`);
      if (name === 'getBytes') {
        const data = o && o.kind === 'string' ? Buffer.from(o.val as string, 'utf8') : Buffer.alloc(0);
        this.ret(cpu, this.newHandle({ kind: 'bytearray', val: new Uint8Array(data) }));
        return;
      }
      if (name === 'getPackageName') {
        this.ret(cpu, this.newHandle({ kind: 'string', val: 'com.ss.android.ugc.aweme' }));
        return;
      }
      // badger 用它拿 ClassLoader，随后 loadClass 反射调用 Java 采集接口
      if (name === 'getClassLoader') {
        this.ret(cpu, this.newHandle({ kind: 'object', val: 'classloader' }));
        return;
      }
      if (name === 'findClass' || name === 'loadClass') {
        const va = new VaList(this.mem, x3, info ? info[3] : 'L');
        const a = this.obj(va.next());
        const nm = a && a.kind === 'string' ? (a.val as string).replace(/\./g, '/') : '?';
        const h = this.newHandle({ kind: 'class', val: nm });
        this.classes.set(h, nm);
        this.ret(cpu, h);
        return;
      }
      const va = info ? new VaList(this.mem, x3, info[3]) : null;
      const r = this.jcall(o, name, va, info ? info[3] : '');
      if (r !== undefined) {
        this.ret(cpu, r);
        return;
      }
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'CallBooleanMethodV' || sem === 'CallIntMethodV'
      || sem === 'CallLongMethodV' || sem === 'CallVoidMethodV') {
      const o = this.obj(x1);
      const info = this.methods.get(x2);
      const va = info ? new VaList(this.mem, x3, info[3]) : null;
      const r = this.jcall(o, info ? info[1] : '?', va, info ? info[3] : '');
      if (sem === 'CallVoidMethodV') {
        this.ret(cpu, 0);
        return;
      }
      const v = r ? this.obj(r)?.val : undefined;
      const n = typeof v === 'boolean' ? (v ? 1 : 0) : Number(v ?? 0);
      this.ret(cpu, sem === 'CallBooleanMethodV' ? (n !== 0 ? 1 : 0) : n);
      return;
    }
    if (sem === 'CallStaticObjectMethodV') {
      const info = this.methods.get(x2);
      const name = info ? info[1] : '?';
      const cls = info ? info[0] : '?';
      if (info && name === 'b' && cls.includes('MS')) {
        const va = new VaList(this.mem, x3, info[3]);
        const op = va.next();
        va.next();
        va.next();
        const a3 = va.next();
        const a4 = va.next();
        if (this.verbose) {
          console.log(`[MS.b] op=${op} arg3=${JSON.stringify(this.obj(a3)?.val ?? null)} arg4=${JSON.stringify(this.obj(a4)?.val ?? null)}`);
        }
        this.ret(cpu, this.msB(op, a3, a4));
        return;
      }
      if (name === 'valueOf' && cls === 'java/lang/Boolean') {
        const va = new VaList(this.mem, x3, info![3]);
        this.ret(cpu, this.newHandle({ kind: 'boolean', val: va.next() !== 0 }));
        return;
      }
      if (name === 'valueOf' && cls === 'java/lang/Long') {
        const va = new VaList(this.mem, x3, info![3]);
        this.ret(cpu, this.newHandle({ kind: 'long', val: va.next() }));
        return;
      }
      if (this.verbose) console.log(`[call] static ${cls}.${name} -> null`);
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'GetArrayLength') {
      const o = this.obj(x1);
      const n = o && (o.kind === 'bytearray' || o.kind === 'objarray')
        ? (o.kind === 'bytearray' ? (o.val as Uint8Array).length : (o.val as number[]).length)
        : 0;
      this.ret(cpu, n);
      return;
    }
    if (sem === 'NewObjectArray') {
      this.ret(cpu, this.newHandle({ kind: 'objarray', val: new Array(x1 & 0xffffffff).fill(0) }));
      return;
    }
    if (sem === 'SetObjectArrayElement') {
      const arr = this.obj(x1);
      const i = x2 & 0xffffffff;
      if (arr && arr.kind === 'objarray' && i >= 0 && i < (arr.val as number[]).length) {
        (arr.val as number[])[i] = x3;
      }
      if (this.verbose) {
        const v = this.obj(x3);
        console.log(`[set] [${i}] = ${JSON.stringify(v?.val ?? null)}`);
      }
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'GetByteArrayRegion') {
      const arr = this.obj(x1);
      const start = x2 & 0xffffffff;
      const ln = x3 & 0xffffffff;
      if (arr && arr.kind === 'bytearray') {
        const src = arr.val as Uint8Array;
        const buf = new Uint8Array(ln);
        buf.set(src.subarray(start, Math.min(start + ln, src.length)));
        this.mem.load(x4, buf);
      }
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'NewByteArray') {
      this.ret(cpu, this.newHandle({ kind: 'bytearray', val: new Uint8Array(x1 & 0xffffffff) }));
      return;
    }
    if (sem === 'GetByteArrayElements') {
      const o = this.obj(x1);
      const src = o && o.kind === 'bytearray' ? (o.val as Uint8Array) : new Uint8Array(0);
      const p = this.arrMem;
      this.arrMem += 0x10000;
      this.mem.map(p, Math.max(1, src.length));
      this.mem.load(p, src);
      this.arrPtr.set(p, x1);
      // isCopy 非空时告知 native 拿到的是副本，它会走 Release 提交
      if (x2) this.mem.write(x2, 4, 1n);
      this.ret(cpu, p);
      return;
    }
    if (sem === 'ReleaseByteArrayElements') {
      const h = this.arrPtr.get(x2);
      const o = h !== undefined ? this.obj(h) : undefined;
      if (o && o.kind === 'bytearray') {
        const dst = o.val as Uint8Array;
        for (let i = 0; i < dst.length; i++) dst[i] = this.mem.ld8(x2 + i);
      }
      this.arrPtr.delete(x2);
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'SetByteArrayRegion') {
      const o = this.obj(x1);
      if (o && o.kind === 'bytearray') {
        const dst = o.val as Uint8Array;
        const start = x2 & 0xffffffff;
        const ln = x3 & 0xffffffff;
        for (let i = 0; i < ln && start + i < dst.length; i++) dst[start + i] = this.mem.ld8(x4 + i);
      }
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'GetObjectClass') {
      const o = this.obj(x1);
      const nm = this.className(o);
      const h = this.newHandle({ kind: 'class', val: nm });
      this.classes.set(h, nm);
      this.ret(cpu, h);
      return;
    }
    if (sem === 'FindClass') {
      const nm = this.mem.cstr(x1);
      if (this.verbose) console.log(`[find] ${nm}`);
      const h = this.newHandle({ kind: 'class', val: nm });
      this.classes.set(h, nm);
      this.ret(cpu, h);
      return;
    }
    if (sem === 'GetSuperclass') {
      const h = this.newHandle({ kind: 'class', val: 'java/lang/Object' });
      this.classes.set(h, 'java/lang/Object');
      this.ret(cpu, h);
      return;
    }
    if (sem === 'NewGlobalRef') {
      this.ret(cpu, x1);
      return;
    }
    if (sem === 'GetObjectRefType') {
      this.ret(cpu, 1); // JNILocalRefType
      return;
    }
    if (sem === 'GetVersion') {
      this.ret(cpu, 0x00010006);
      return;
    }
    if (sem === 'RegisterNatives') {
      if (this.opts.cold) {
        // JNI 标准布局是 x2=methods、x3=count；metasec 的 trampoline 把 methods 放在 x3
        const n2 = x3 >>> 0;
        if (n2 > 0 && n2 < 200 && this.methodsAt(x2)) this.coldRegisterNatives(x2, n2);
        else this.coldRegisterNatives(x3, x4);
      }
      this.ret(cpu, 0);
      return;
    }
    if (sem === 'ExceptionCheck' || sem === 'ExceptionClear' || sem === 'ExceptionOccurred'
      || sem === 'DeleteGlobalRef' || sem === 'DeleteLocalRef' || sem === 'EnsureLocalCapacity'
      || sem === 'PushLocalFrame' || sem === 'PopLocalFrame') {
      this.ret(cpu, 0);
      return;
    }
    if (this.verbose) {
      console.log(`[jni] !! unimplemented ${key} (idx=${idx} imm=0x${imm.toString(16)}) x1=0x${x1.toString(16)} x2=0x${x2.toString(16)} x3=0x${x3.toString(16)}`);
    }
    this.ret(cpu, 0);
  }

  /** MsJni.callStaticObjectMethodV 里 MS.b 的等价语义 */
  private msB(op: number, a3: number, a4: number): number {
    void a3;
    void a4;
    if (op === 65537) return this.newHandle({ kind: 'string', val: '40.5.0' });
    if (op === 65538) return this.newHandle({ kind: 'string', val: 'com.ss.android.ugc.aweme' });
    if (op === 65539) return this.newHandle({ kind: 'string', val: '/data/user/0/com.ss.android.ugc.aweme/files' });
    if (op === 33554433 || op === 33554434) return this.newHandle({ kind: 'boolean', val: true });
    return 0;
  }

  /** 句柄对应的 Java 类名（native 会用它取 GetObjectClass 结果再反射找方法） */
  private className(o: Obj | undefined): string {
    if (!o) return '?';
    switch (o.kind) {
      case 'string': return 'java/lang/String';
      case 'bytearray': return '[B';
      case 'boolean': return 'java/lang/Boolean';
      case 'long': return 'java/lang/Long';
      case 'map': return 'java/util/HashMap';
      case 'set': return 'java/util/HashSet';
      case 'iter': return 'java/util/Iterator';
      case 'entry': return 'java/util/Map$Entry';
      case 'json': return 'org/json/JSONObject';
      case 'class': return 'java/lang/Class';
      default: return 'java/lang/Object';
    }
  }

  /** 句柄 → 字符串（Map 键比较用） */
  private str(h: number): string {
    const o = this.obj(h);
    if (!o) return '';
    return typeof o.val === 'string' ? o.val : String(o.val);
  }

  /** JS 值 → Java 句柄 */
  private jval(v: unknown): number {
    if (v === null || v === undefined) return 0;
    if (typeof v === 'string') return this.newHandle({ kind: 'string', val: v });
    if (typeof v === 'boolean') return this.newHandle({ kind: 'boolean', val: v });
    if (typeof v === 'number') return this.newHandle({ kind: 'long', val: v });
    if (Array.isArray(v)) return this.newHandle({ kind: 'objarray', val: v.map((x) => this.jval(x)) });
    return this.newHandle({ kind: 'json', val: v });
  }

  /**
   * 通用 Java 侧方法：HashMap / HashSet / Iterator / Map$Entry / JSONObject。
   * 未命中返回 undefined（调用方回 0）。
   */
  private jcall(o: Obj | undefined, name: string, va: VaList | null, sig: string): number | undefined {
    if (!o) return undefined;
    if (name === 'toString') {
      const v = o.val;
      return this.newHandle({ kind: 'string', val: typeof v === 'string' ? v : JSON.stringify(v ?? null) });
    }
    if (name === 'hashCode') return this.newHandle({ kind: 'long', val: 0 });
    if (name === 'equals') return this.newHandle({ kind: 'boolean', val: true });
    if (name === 'getClass') return this.newHandle({ kind: 'class', val: this.className(o) });
    if (o.kind === 'map') {
      const pairs = o.val as Array<[number, number]>;
      if (name === 'size') return this.newHandle({ kind: 'long', val: pairs.length });
      if (name === 'isEmpty') return this.newHandle({ kind: 'boolean', val: pairs.length === 0 });
      if (name === 'entrySet' || name === 'keySet' || name === 'values') {
        const items = name === 'entrySet'
          ? pairs.map(([k, v]) => this.newHandle({ kind: 'entry', val: [k, v] }))
          : pairs.map(([k, v]) => (name === 'keySet' ? k : v));
        return this.newHandle({ kind: 'set', val: items });
      }
      if (name === 'get' && va) {
        const key = this.str(va.next());
        if (this.verbose) console.log(`[map] get(${key})`);
        const hit = pairs.find(([k]) => this.str(k) === key);
        return hit ? hit[1] : 0;
      }
      if (name === 'containsKey' && va) {
        const key = this.str(va.next());
        return this.newHandle({ kind: 'boolean', val: pairs.some(([k]) => this.str(k) === key) });
      }
      if (name === 'put' && va) {
        const kh = va.next();
        const vh = va.next();
        const key = this.str(kh);
        const i = pairs.findIndex(([k]) => this.str(k) === key);
        if (i < 0) {
          pairs.push([kh, vh]);
          return 0;
        }
        const old = pairs[i][1];
        pairs[i][1] = vh;
        return old;
      }
      return undefined;
    }
    if (o.kind === 'set') {
      const items = o.val as number[];
      if (name === 'size') return this.newHandle({ kind: 'long', val: items.length });
      if (name === 'isEmpty') return this.newHandle({ kind: 'boolean', val: items.length === 0 });
      if (name === 'iterator') return this.newHandle({ kind: 'iter', val: { items, i: 0 } });
      return undefined;
    }
    if (o.kind === 'iter') {
      const it = o.val as { items: number[]; i: number };
      if (name === 'hasNext') return this.newHandle({ kind: 'boolean', val: it.i < it.items.length });
      if (name === 'next') return it.i < it.items.length ? it.items[it.i++] : 0;
      return undefined;
    }
    if (o.kind === 'entry') {
      const [k, v] = o.val as [number, number];
      if (name === 'getKey') return k;
      if (name === 'getValue') return v;
      return undefined;
    }
    if (o.kind === 'json') {
      const j = o.val as Record<string, unknown>;
      const get = (key: string): unknown => (Object.prototype.hasOwnProperty.call(j, key) ? j[key] : undefined);
      if (name === 'length' || name === 'size') return this.newHandle({ kind: 'long', val: Object.keys(j).length });
      if (name === 'names' || name === 'keys') {
        const items = Object.keys(j).map((k) => this.newHandle({ kind: 'string', val: k }));
        return this.newHandle({ kind: 'iter', val: { items, i: 0 } });
      }
      if (name === 'has' && va) {
        const key = this.str(va.next());
        return this.newHandle({ kind: 'boolean', val: get(key) !== undefined });
      }
      if (name === 'isNull' && va) {
        const key = this.str(va.next());
        const v = get(key);
        return this.newHandle({ kind: 'boolean', val: v === null || v === undefined });
      }
      if (!va) return undefined;
      const key = this.str(va.next());
      const v = get(key);
      if (this.verbose) console.log(`[json] ${name}(${key}) -> ${JSON.stringify(v)}`);
      const missing = v === undefined || v === null;
      if (name.startsWith('opt')) {
        if (!missing) return this.jval(v);
        if (shorty(sig).length > 1) return va.next();
        if (name.includes('String')) return this.newHandle({ kind: 'string', val: '' });
        if (name.includes('Boolean')) return this.newHandle({ kind: 'boolean', val: false });
        return this.newHandle({ kind: 'long', val: 0 });
      }
      return missing ? 0 : this.jval(v);
    }
    if (o.kind === 'long' || o.kind === 'boolean') {
      if (name === 'intValue' || name === 'longValue' || name === 'byteValue'
        || name === 'shortValue' || name === 'doubleValue' || name === 'floatValue'
        || name === 'booleanValue') {
        return this.newHandle({ kind: 'long', val: o.val });
      }
      return undefined;
    }
    return undefined;
  }

  // ---------------------------------------------------------------- syscall

  private doSyscall(cpu: Cpu, nr: number): void {
    if (this.opts.cold) {
      this.coldSyscall(cpu, nr);
      return;
    }
    const x0 = Number(cpu.x[0]);
    const x1 = Number(cpu.x[1]);
    const x2 = Number(cpu.x[2]);
    this.svcLog.push(nr);
    switch (nr) {
      case 174: // getuid
      case 175: // geteuid
        cpu.x[0] = 0n;
        return;
      case 172: // getpid
      case 173: // getppid
      case 178: // gettid
      case 96: // set_tid_address
        cpu.x[0] = BigInt(this.pid);
        return;
      case 56: { // openat
        const path = this.mem.cstr(x1);
        const fd = this.sysOpen(path);
        if (this.verbose) console.log(`[sys] openat(${JSON.stringify(path)}, 0x${(x2 & 0xffffffff).toString(16)}) => ${fd}`);
        // 与 oracle 一致：返回值按 32 位零扩展（失败时 0xfffffffe）
        cpu.x[0] = BigInt.asUintN(32, BigInt(fd));
        return;
      }
      case 48: // faccessat
      case 34: // mkdirat
      case 79: // newfstatat
        // 与 oracle 一致：错误码按 32 位零扩展（0xfffffffe），不能符号扩展到 64 位
        cpu.x[0] = 0xfffffffen;
        return;
      case 80: // fstat
        this.sysFstat(x0 & 0xffffffff, x1);
        cpu.x[0] = 0n;
        return;
      case 63: { // read
        const n = this.sysRead(x0 & 0xffffffff, x1, x2);
        if (this.verbose) console.log(`[sys] read(fd=${x0}, n=${x2}) => ${n}`);
        cpu.x[0] = BigInt.asUintN(32, BigInt(n));
        return;
      }
      case 64: // write
        if (this.verbose) console.log(`[sys] write(fd=${x0}, n=${x2})`);
        cpu.x[0] = BigInt(x2 & 0xffffffff);
        return;
      case 57: // close
        this.fds.delete(x0 & 0xffffffff);
        cpu.x[0] = 0n;
        return;
      case 113: { // clock_gettime
        const [sec, nsec] = x0 === 0 || x0 === 5 ? [this.ts, FROZEN_SUB] : this.monoTime();
        if (x1) {
          this.mem.write(x1, 8, BigInt(sec));
          this.mem.write(x1 + 8, 8, BigInt(nsec));
        }
        cpu.x[0] = 0n;
        return;
      }
      case 169: // gettimeofday
        if (x0) {
          this.mem.write(x0, 8, BigInt(this.ts));
          this.mem.write(x0 + 8, 8, BigInt(FROZEN_SUB));
        }
        cpu.x[0] = 0n;
        return;
      case 278: { // getrandom
        const n = x1 & 0xffffffff;
        if (x0) this.mem.load(x0, new Uint8Array(n));
        cpu.x[0] = BigInt(n);
        return;
      }
      case 99: // set_robust_list
      case 167: // prctl
      case 98: // futex
      case 226: // mprotect
      case 215: // munmap
        cpu.x[0] = 0n;
        return;
      case 222: // mmap
      case 220: // clone
        cpu.x[0] = 0xffffffffffffffffn;
        return;
      default:
        this.stopReason = `unimplemented syscall nr=${nr} pc=0x${(cpu.pc - 4).toString(16)} lr=0x${Number(cpu.x[30]).toString(16)} x0=0x${x0.toString(16)} x1=0x${x1.toString(16)} x2=0x${x2.toString(16)}`;
        if (this.verbose) console.log('[sys] !! ' + this.stopReason);
        throw new Error(this.stopReason);
    }
  }

  private sysOpen(path: string): number {
    if (path === '/dev/urandom' || path === '/dev/random') {
      const fd = this.nextFd;
      this.nextFd += 1;
      this.fds.set(fd, { kind: 'urandom', data: null });
      return fd;
    }
    // /proc/self/cmdline、mssdk 目录、.msp_ / .msf3_ 等在 unidbg 里都不存在
    return -2;
  }

  private sysFstat(fd: number, buf: number): void {
    if (!buf) return;
    this.mem.load(buf, new Uint8Array(128));
    const ent = this.fds.get(fd);
    if (!ent) return;
    const size = ent.kind === 'urandom' ? 512 : (ent.data ? ent.data.length : 0);
    this.mem.write(buf + 16, 4, BigInt(0x81a4)); // st_mode = S_IFREG|0644
    this.mem.write(buf + 20, 4, 1n); // st_nlink
    this.mem.write(buf + 48, 8, BigInt(size)); // st_size
    this.mem.write(buf + 56, 8, 4096n); // st_blksize
    this.mem.write(buf + 64, 8, BigInt(Math.ceil(size / 512))); // st_blocks
  }

  private sysRead(fd: number, buf: number, count: number): number {
    const ent = this.fds.get(fd);
    if (!ent) return -9;
    if (ent.kind === 'urandom') {
      const n = Math.min(count, 512);
      this.mem.load(buf, new Uint8Array(n));
      return n;
    }
    if (ent.data) {
      const n = Math.min(count, ent.data.length);
      this.mem.load(buf, ent.data.subarray(0, n));
      return n;
    }
    return 0;
  }

  // ---------------------------------------------------------------- 运行

  run(): SoSignResult {
    if (this.opts.cold) return this.runCold();
    this.load();
    this.patchInitTime();
    this.setRegs();
    this.decodeJniTable();
    this.installHooks();

    const cpu = this.cpu;
    cpu.svc = (c, imm) => this.onSvc(c, imm);
    cpu.tick = this.maxSteps;
    if (this.verbose) {
      console.log(`[run] entry=0x${this.entryPc.toString(16)} sp=0x${this.regs.sp.toString(16)} url_handle=0x${this.urlHandle.toString(16)} url_len=${this.opts.url.length}`);
    }

    this.steps = 0;
    this.pcIndex = 0;
    for (;;) {
      if (cpu.pc === this.retPc) {
        this.donePc = cpu.pc;
        break;
      }
      // pcIndex 与 Python oracle 的 UC_HOOK_CODE 计数一致（pcHook 命中也算一条）
      const idx = this.pcIndex++;
      if (process.env.SO_PROGRESS && idx % 20000 === 0) {
        console.log(`[p] #${idx} pc=+0x${(cpu.pc - this.base).toString(16)} steps=${this.steps}`);
      }
      // 先记录 pc，再执行 pcHook：与 Python oracle 的 UC_HOOK_CODE 语义对齐
      if (this.tracePc && idx < this.tracePc) this.pcSeq.push(cpu.pc);
      const h = this.pcHooks.get(cpu.pc);
      if (h && h(cpu)) {
        continue;
      }
      if (this.steps >= this.maxSteps) {
        this.stopReason = `指令预算耗尽 @0x${cpu.pc.toString(16)}`;
        break;
      }
      if (this.stepDump && idx === this.stepDump) {
        const rs: string[] = [];
        for (let i = 0; i <= 30; i++) rs.push(`x${i}=0x${cpu.x[i].toString(16)}`);
        console.log(`[step] #${idx} pc=0x${cpu.pc.toString(16)} sp=0x${cpu.x[31].toString(16)} ` +
          `nzcv=${cpu.nzcv}\n[step] ${rs.join(' ')}`);
        this.stopReason = 'step dump';
        break;
      }
      if (this.regPc && cpu.pc - this.base === this.regPc) {
        const rs: string[] = [];
        for (let i = 0; i <= 30; i++) rs.push(`x${i}=0x${cpu.x[i].toString(16)}`);
        console.log(`[regs] #${this.steps} +0x${this.regPc.toString(16)} nzcv=${cpu.nzcv} ` +
          `sp=0x${cpu.x[31].toString(16)}\n[regs] ${rs.join(' ')}`);
        const b = Number(cpu.x[4]);
        try {
          console.log(`[regs] [x4]=0x${this.mem.read(b, 8).toString(16)} ` +
            `[x4+8]=0x${this.mem.read(b + 8, 8).toString(16)}`);
        } catch { /* 地址不可读 */ }
        const vs: string[] = [];
        for (let i = 0; i < 8; i++) {
          vs.push(`v${i}=${cpu.vhi(i).toString(16).padStart(16, '0')}${cpu.vlo(i).toString(16).padStart(16, '0')}`);
        }
        console.log(`[regs] ${vs.join(' ')}`);
      }
      if (this.trace && cpu.pc - this.base === 0x1882fc) {
        const a = Number(cpu.x[0]);
        console.log(`[probe] x0=0x${a.toString(16)} [x0]=0x${this.mem.fetch(a).toString(16)} ` +
          `[x0+4]=0x${this.mem.fetch(a + 4).toString(16)}`);
      }
      if (this.trace && this.steps < this.trace) {
        const w = this.mem.fetch(cpu.pc);
        console.log(`[t] #${this.steps} +0x${(cpu.pc - this.base).toString(16)} ` +
          `w=${w.toString(16).padStart(8, '0')} x0=0x${cpu.x[0].toString(16)} ` +
          `x1=0x${cpu.x[1].toString(16)} x2=0x${cpu.x[2].toString(16)} x8=0x${cpu.x[8].toString(16)} ` +
          `x15=0x${cpu.x[15].toString(16)} x16=0x${cpu.x[16].toString(16)} ` +
          `x17=0x${cpu.x[17].toString(16)} x29=0x${cpu.x[29].toString(16)} ` +
          `sp=0x${cpu.x[31].toString(16)}`);
      }
      if (this.tailN) {
        let w = 0;
        try {
          w = this.mem.fetch(cpu.pc);
        } catch {
          w = 0;
        }
        this.tailBuf.push(`#${this.steps} +0x${(cpu.pc - this.base).toString(16)} ` +
          `w=${w.toString(16).padStart(8, '0')} x0=0x${cpu.x[0].toString(16)} ` +
          `x1=0x${cpu.x[1].toString(16)} x8=0x${cpu.x[8].toString(16)} x30=0x${cpu.x[30].toString(16)}`);
        if (this.tailBuf.length > this.tailN) this.tailBuf.shift();
      }
      try {
        cpu.step();
      } catch (e) {
        const msg = (e as Error).message;
        if (cpu.pc === this.retPc) {
          this.donePc = cpu.pc;
          break;
        }
        this.stopReason = `异常 ${msg} @pc=0x${cpu.pc.toString(16)} lr=0x${Number(cpu.x[30]).toString(16)}`;
        break;
      }
      this.steps += 1;
    }

    if (this.tailN) for (const s of this.tailBuf) console.log(`[tail] ${s}`);

    const retObj = this.obj(Number(cpu.x[0]));
    const headers: Record<string, string> = {};
    if (retObj && retObj.kind === 'objarray') {
      const items = retObj.val as number[];
      for (let i = 0; i + 1 < items.length; i += 2) {
        const k = this.obj(items[i]);
        const v = this.obj(items[i + 1]);
        if (k && k.kind === 'string') {
          headers[k.val as string] = v && v.kind === 'string' ? (v.val as string) : String(v?.val ?? '');
        }
      }
    }
    return {
      headers,
      stopReason: this.stopReason || (this.donePc !== null ? `normal return to 0x${this.donePc.toString(16)}` : 'unknown'),
      steps: this.steps,
      jniCalls: { ...this.jniCount },
      syscalls: [...new Set(this.svcLog)].sort((a, b) => a - b),
      newStrings: this.nstr,
      retObj,
    };
  }

  // ---------------------------------------------------------------- 冷启动

  private envPtr(): number {
    return this.opts.cold ? this.coldEnv : this.regs.x0;
  }

  /** 冷加载：系统库 + libmetasec_ml.so，不读 state_a 快照 */
  private loadCold(): void {
    const c = this.opts.cold!;
    const libs = [
      { name: 'libc.so', base: 0x405b0000 },
      { name: 'libdl.so', base: 0x40590000 },
      { name: 'libm.so', base: 0x406a0000 },
      { name: 'liblog.so', base: 0x40470000 },
    ];
    for (const l of libs) {
      this.coldLibs.push({ name: l.name, img: new ElfImage(join(c.libDir, l.name)), base: l.base });
    }
    this.coldMeta = new ElfImage(c.soPath);

    // 全局符号表：先加载的库优先，so 自身导出也参与解析
    for (const l of this.coldLibs) {
      for (const [n, v] of l.img.exports) if (!this.coldGlobals.has(n)) this.coldGlobals.set(n, l.base + v);
    }
    for (const [n, v] of this.coldMeta.exports) {
      if (!this.coldGlobals.has(n)) this.coldGlobals.set(n, SO_BASE + v);
    }
    const resolve = (name: string): number => this.coldGlobals.get(name) ?? 0;

    for (const l of this.coldLibs) {
      mapImage(this.mem, l.img, l.base);
      this.segs.push([l.base, l.img.extent]);
    }
    for (const l of this.coldLibs) applyRelocs(this.mem, l.img, l.base, resolve);
    mapImage(this.mem, this.coldMeta, SO_BASE);
    this.segs.push([SO_BASE, this.coldMeta.extent]);
    const st = applyRelocs(this.mem, this.coldMeta, SO_BASE, resolve);
    if (this.verbose) {
      console.log(
        `[cold] libmetasec extent=0x${this.coldMeta.extent.toString(16)} ` +
          `reloc=${st.applied}/${this.coldMeta.relocs.length} und=${st.unresolved.size}` +
          (st.unresolved.size ? ` [${[...st.unresolved.keys()].join(',')}]` : ''),
      );
    }

    // 栈 + TLS（与 unidbg 快照一致：sp=0xbffff700，tpidr=sp+8）
    this.mem.map(0xbf000000, 0x1000000);
    this.segs.push([0xbf000000, 0x1000000]);
    // 堆：预映射 64MiB，bump 分配（不回收）
    this.mem.map(this.coldHeap, 0x4000000);
    this.segs.push([this.coldHeap, 0x4000000]);
    // 签名阶段回放 oracle dlmalloc 地址（覆盖 0x40780000..0x40b80000 的全部堆区）
    this.mem.map(0x40700000, 0x5000000);
    this.segs.push([0x40700000, 0x5000000]);

    this.base = SO_BASE;
    this.coldInitArray = readInitArray(this.mem, this.coldMeta, SO_BASE);
    const onload = this.coldMeta.exports.get('JNI_OnLoad') ?? 0;
    this.coldJniOnLoad = onload ? SO_BASE + onload : 0;
    this.mmapNext = Math.max(0x41000000, SO_BASE + this.coldMeta.extent);

    this.cpu = new Cpu(this.mem);
    this.cpu.tpidr = BigInt(this.coldSp + 8);

    this.objs.set(this.coldApplication, { kind: 'object', val: 'application' });
    this.objs.set(this.coldClassHandle, { kind: 'class', val: 'com/bytedance/mobsec/metasec/ml/MS' });
    this.classes.set(this.coldClassHandle, 'com/bytedance/mobsec/metasec/ml/MS');

    this.coldInstallLibHooks();

    if (this.watchSpec) {
      const [lo, len] = this.watchSpec;
      this.mem.watch = {
        lo,
        hi: lo + len,
        cb: (a, s, v) => console.log(`[memwr] #${this.steps} pc=+0x${(this.cpu.pc - this.base).toString(16)} ` +
          `addr=0x${a.toString(16)} size=${s} v=0x${v.toString(16)}`),
      };
    }
    if (process.env.SO_CTXLOG) {
      this.ctxTrace = [];
      this.mem.watch = {
        lo: 0xbfffdd00,
        hi: 0xbfffe100,
        cb: (a, _s, v) => {
          const pc = this.cpu.pc - 4 - this.base;
          if (a === 0xbfffde64 && pc === 0x18a898) {
            this.ctxTrace.push('END');
            this.mem.watch = null;
            return;
          }
          this.ctxTrace.push(`${pc.toString(16)} ${a.toString(16)} ${v.toString(16)}`);
          if (this.ctxTrace.length > 6000) this.ctxTrace.splice(0, 1000);
        },
      };
    }
    if (process.env.SO_BBLOG) {
      // 基本块级对拍：首次写 Medusa 体源缓冲 0x40ad4380 时开始记录块首 pc 与内存读
      this.bbActive = false;
      this.bbPrev = -1;
      this.bbBlocks = [];
      this.bbReads = [];
      this.mem.watch = {
        lo: 0x40ad4380,
        hi: 0x40ad4380 + 0x330,
        cb: () => {
          if (this.bbActive) return;
          this.bbActive = true;
          this.mem.watchRead = {
            cb: (a, s, v) => {
              this.bbReads.push(
                `${(this.cpu.pc - SO_BASE).toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
            },
          };
        },
      };
      // 谁写了 0x407bf000..0x407c0000 的 VM 字节码副本（oracle/TS 首个数据分叉处）
      this.bbWrites = [];
      this.mem.watch2 = {
        lo: 0x407bf000,
        hi: 0x407c0000,
        cb: (a, s, v) => {
          this.bbWrites.push(
            `${(this.cpu.pc - SO_BASE).toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
        },
      };
      // 桩层用 mem.copy/fill/load 会绕过 watch2，这里包装一层补记
      const inRegion = (a: number): boolean => a >= 0x407bf000 && a < 0x407c0000;
      const oc = this.mem.copy.bind(this.mem);
      this.mem.copy = (d, s, n) => {
        if (inRegion(d)) {
          this.bbWrites.push(`copy dst=0x${d.toString(16)} src=0x${s.toString(16)} n=${n} ` +
            `lr=+0x${(Number(this.cpu.x[30]) - SO_BASE).toString(16)} ` +
            `data=${Buffer.from(this.mem.slice(s, Math.min(n, 40))).toString('hex')}`);
        }
        oc(d, s, n);
      };
      const of = this.mem.fill.bind(this.mem);
      this.mem.fill = (d, v, n) => {
        if (inRegion(d)) this.bbWrites.push(`fill dst=0x${d.toString(16)} v=${v} n=${n}`);
        of(d, v, n);
      };
      const ol = this.mem.load.bind(this.mem);
      this.mem.load = (d, b) => {
        if (inRegion(d)) this.bbWrites.push(`load dst=0x${d.toString(16)} n=${b.length}`);
        ol(d, b);
      };
    }
    if (process.env.SO_VM1DUMP) {
      // 首次由 VM store 指令写 0x40ad4380 时 dump 寄存器与关键内存区（与 oracle 对拍）
      let vm1Done = false;
      this.mem.watch = {
        lo: 0x40ad4380,
        hi: 0x40ad4380 + 0x2e3,
        cb: (a) => {
          if (vm1Done || a !== 0x40ad4380) return;
          const pc = this.cpu.pc - 4 - SO_BASE;
          if (pc !== 0x18b254) return;
          vm1Done = true;
          const regs: string[] = [];
          for (let r = 0; r <= 28; r++) regs.push(`x${r}=${this.cpu.x[r].toString(16)}`);
          regs.push(`lr=${this.cpu.x[30].toString(16)}`);
          writeFileSync('d:/there/douyinhook/unidbg_work/vm1in_ts.txt',
            ['TS', `pc=${pc.toString(16)} sp=${this.cpu.x[31].toString(16)}`].concat(regs).join('\n') + '\n' +
            'stack_bfffa000=' + Buffer.from(this.mem.slice(0xbfffa000, 0x4800)).toString('hex') + '\n' +
            'heap_40780000=' + Buffer.from(this.mem.slice(0x40780000, 0x5000)).toString('hex') + '\n' +
            'ad_40ad0000=' + Buffer.from(this.mem.slice(0x40ad0000, 0x4800)).toString('hex') + '\n');
          this.mem.watch = null;
        },
      };
    }
    if (process.env.SO_RFLOG) {
      // 窗口：默认从 S2 缓冲首次 VM store(0x407bf4ff) 起；SO_RFGATE 可指定更早的开门地址
      // watch = regfile 写入；watch2 = S2 缓冲 VM store（S 标记）；watch3 = 门控地址
      const rfGate = process.env.SO_RFGATE ? Number.parseInt(process.env.SO_RFGATE, 16) : 0x407bf4ff;
      this.rfLog = [];
      this.mem.watch = {
        lo: 0xbfffcba8,
        hi: 0xbfffcba8 + 0x1000,
        cb: (a, s, v) => {
          if (!this.rfOn || this.rfLog.length >= 2000000) return;
          this.rfLog.push(`${(this.cpu.pc - 4 - SO_BASE).toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
        },
      };
      this.mem.watch2 = {
        lo: 0x407bf400,
        hi: 0x407bf71b,
        cb: (a, s, v) => {
          if (a === 0x407bf4ff) this.rfOn = true;
          if (!this.rfOn || this.rfLog.length >= 2000000) return;
          this.rfLog.push(`S ${a.toString(16)} ${s} ${v.toString(16)}`);
        },
      };
      if (rfGate !== 0x407bf4ff) {
        this.mem.watch3 = { lo: rfGate, hi: rfGate + 1, cb: () => { this.rfOn = true; } };
      }
    }
    if (process.env.SO_WLOG) {
      const [ls, hs] = process.env.SO_WLOG.split('-');
      const lo = Number.parseInt(ls, 16);
      const hi = Number.parseInt(hs, 16);
      this.wlog = [];
      this.mem.watch = {
        lo,
        hi,
        cb: (a, s, v) => {
          if (this.wlog.length < 400000) {
            const pc = this.cpu.pc - 4 - SO_BASE;
            let extra = '';
            if (pc === 0x18b254) {
              extra = ` r=${this.cpu.x[17]} b=${this.cpu.x[4]} i=${this.cpu.x[16]} v14=${this.cpu.x[14]}`;
            }
            this.wlog.push(`W ${pc.toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}${extra}`);
          }
        },
      };
    }
    if (process.env.SO_WATCHADDR) {
      const lo = Number.parseInt(process.env.SO_WATCHADDR, 16);
      this.ctxTrace = [];
      this.mem.watch = {
        lo,
        hi: lo + 0x20,
        cb: (a, s, v) => {
          const pc = this.cpu.pc - 4 - this.base;
          this.ctxTrace.push(`${pc.toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
          if (this.ctxTrace.length > 20000) this.ctxTrace.splice(0, 2000);
        },
      };
    }
    if (process.env.SO_FRAMELOG) {
      const lo = Number.parseInt(process.env.SO_FRAMELOG, 16);
      this.ctxTrace = [];
      this.mem.watch = {
        lo,
        hi: lo + 0x1000,
        cb: (a, s, v) => {
          const pc = this.cpu.pc - 4 - this.base;
          this.ctxTrace.push(`${pc.toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
        },
      };
    }
  }

  /** 自建 JNIEnv / JavaVM：每个槽都是 `svc #(0x100+i); ret` 桩 */
  private coldBuildJni(): void {
    const region = 0xfffd0000;
    const stubBase = 0xfffe0000;
    const envTbl = 0xfffe1400;
    const vmTbl = 0xfffe1e00;
    this.mem.map(region, 0x20000);
    this.segs.push([region, 0x20000]);

    const putStub = (p: number, imm: number): void => {
      this.mem.write(p, 4, BigInt((0xd4000001 | ((imm & 0xffff) << 5)) >>> 0));
      this.mem.write(p + 4, 4, 0xd65f03c0n);
    };
    for (let i = 0; i < 260; i++) {
      const p = stubBase + i * 0x10;
      putStub(p, 0x100 + i);
      this.mem.write(envTbl + i * 8, 8, BigInt(p));
      this.imm2jni.set(0x100 + i, i);
    }
    // JavaVM: 3=DestroyJavaVM, 4=Attach, 5=Detach, 6=GetEnv, 7=AttachAsDaemon
    for (let i = 0; i < 8; i++) {
      const p = stubBase + (260 + i) * 0x10;
      putStub(p, 0x300 + i);
      this.mem.write(vmTbl + i * 8, 8, BigInt(p));
      this.imm2jni.set(0x300 + i, 1000 + i);
    }
    this.mem.write(this.coldEnv, 8, BigInt(envTbl));
    this.mem.write(this.coldVm, 8, BigInt(vmTbl));
  }

  /** 最近 512 条指令 pc（按时间顺序） */
  private coldTailText(): string {
    const t = this.coldTail;
    const out: string[] = [];
    for (let i = 0; i < 512; i++) out.push(t[(this.coldTailIdx + i) & 511].toString(16));
    return out.join(' ');
  }

  /** 在冷启动的干净栈上调用一个 so 函数（返回 x0） */
  private coldCall(entry: number, args: number[], budget = this.maxSteps): number {
    const cpu = this.cpu;
    for (let i = 0; i <= 30; i++) cpu.x[i] = 0n;
    for (let i = 0; i < args.length && i < 8; i++) cpu.x[i] = BigInt.asUintN(64, BigInt(args[i]));
    cpu.x[30] = BigInt(this.coldSentinel);
    cpu.x[31] = BigInt(this.coldSp);
    cpu.pc = entry;
    cpu.tick = budget;
    this.steps = 0;
    this.coldTailIdx = 0;
    const rwSpec = process.env.SO_REGWATCH;
    const rwTargets = rwSpec ? new Set(rwSpec.split(',').map((s) => s.toLowerCase())) : undefined;
    const rwPrev: bigint[] = [0n, 0n, 0n, 0n, 0n, 0n];
    if (rwTargets) for (let r = 1; r <= 5; r++) rwPrev[r] = cpu.x[r];
    const hitSpec = process.env.SO_PCHIT;
    const hitSet = hitSpec ? new Set(hitSpec.split(',').map((s) => SO_BASE + Number.parseInt(s, 16))) : undefined;
    const srcPc = process.env.SO_SRCPC ? SO_BASE + Number.parseInt(process.env.SO_SRCPC, 16) : 0;
    const hexPc = process.env.SO_HEXLOG ? SO_BASE + Number.parseInt(process.env.SO_HEXLOG, 16) : 0;
    // 调试开关一次性求值：process.env 的属性访问在 Node 里要几百 ns，
    // 放进 5000 万次的主循环会直接毁掉性能。
    const dbgLdrb = !!process.env.SO_LDRBLOG;
    const dbgB64 = !!process.env.SO_B64LOG;
    const dbgDumpSrc = !!process.env.SO_DUMPSRC;
    const dbgBb = !!process.env.SO_BBLOG;
    const dbgTramp = !!process.env.SO_TRAMPLOG;
    const dbgVmDump = !!process.env.SO_VMDUMP;
    const dbgVmSlot = !!process.env.SO_VMSLOT;
    const dbgVmLoad = !!process.env.SO_VMLOAD;
    const dbgLadon = !!process.env.SO_LADON;
    const verbose = this.verbose;
    if (!dbgLdrb && !dbgB64 && !dbgDumpSrc && !dbgBb && !dbgTramp && !dbgVmDump &&
      !dbgVmSlot && !dbgVmLoad && !dbgLadon && !hitSet && !hexPc && !srcPc &&
      !rwTargets && !verbose) {
      return this.coldCallJit(entry, args, budget);
    }
    for (;;) {
      if (cpu.pc === this.coldSentinel) break;
      const h = this.pcHooks.get(cpu.pc);
      if (h && h(cpu)) continue;
      if (hitSet && hitSet.has(cpu.pc)) {
        const regs: string[] = [];
        for (let r = 0; r <= 17; r++) regs.push(`${r}:${cpu.x[r].toString(16)}`);
        writeFileSync('d:/there/douyinhook/unidbg_work/pchit.txt',
          `pc=+0x${(cpu.pc - SO_BASE).toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} ` +
            `sp=0x${cpu.x[31].toString(16)} ${regs.join(' ')}\n`,
          { flag: 'a' });
      }
      if (hexPc && cpu.pc === hexPc) {
        const n = Number(cpu.x[1]);
        const p = Number(cpu.x[0]);
        writeFileSync('d:/there/douyinhook/unidbg_work/hexlog.txt',
          `len=${n} src=0x${p.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} ` +
            `${Buffer.from(this.mem.slice(p, Math.min(n, 64))).toString('hex')}\n`, { flag: 'a' });
      }
      if (dbgLdrb && cpu.pc === SO_BASE + 0x189a98) {
        const a = Number(cpu.x[16]) + Number(cpu.x[17]);
        this.ldrbLog.push(`${a.toString(16)} ${Number(this.mem.read(a, 1)).toString(16)}`);
      }
      if (dbgB64 && cpu.pc === SO_BASE + 0x2702f4) {
        const len = Number(cpu.x[4]) & 0xffffffff;
        const src = Number(cpu.x[3]);
        const lo = src - 0x40;
        writeFileSync('d:/there/douyinhook/unidbg_work/b64log.txt',
          `len=${len} src=0x${src.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} @0x${lo.toString(16)}\n` +
            `${Buffer.from(this.mem.slice(lo, 0x80)).toString('hex')}\n`, { flag: 'a' });
      }
      if (dbgDumpSrc && cpu.pc === SO_BASE + 0x2b73f4 &&
          Number(cpu.x[0]) === 0x40ad4a80) {
        writeFileSync('d:/there/douyinhook/unidbg_work/body_src_ts.bin',
          this.mem.slice(0x40ad4377, 0x32c));
        process.env.SO_DUMPSRC = '';
      }
      if (dbgBb && this.bbActive) {
        if (cpu.pc === SO_BASE + 0x2b73f4) {
          const a0 = Number(cpu.x[0]);
          if (a0 >= 0x40ad4800 && a0 < 0x40ad5100) {
            writeFileSync('d:/there/douyinhook/unidbg_work/bb_ts.txt',
              this.bbBlocks.map((p) => p.toString(16)).join('\n') + '\n');
            writeFileSync('d:/there/douyinhook/unidbg_work/bb_reads_ts.txt',
              this.bbReads.join('\n') + '\n');
            writeFileSync('d:/there/douyinhook/unidbg_work/bb_wr_ts.txt',
              this.bbWrites.join('\n') + '\n');
            this.bbActive = false;
            this.mem.watch = null;
            this.mem.watchRead = null;
          }
        }
        if (this.bbActive) {
          if (cpu.pc !== this.bbPrev + 4 && cpu.pc >= SO_BASE && cpu.pc < 0x403c7810) {
            this.bbBlocks.push(cpu.pc - SO_BASE);
          }
          this.bbPrev = cpu.pc;
        }
      }
      if (dbgTramp && cpu.pc === SO_BASE + 0x2b73f4) {
        const fn = Number(cpu.x[8]);
        const a0 = Number(cpu.x[0]);
        const a1 = Number(cpu.x[1]);
        const a2 = Number(cpu.x[2]);
        if (a0 >= 0x40ad4800 && a0 < 0x40ad5100) {
          let src = '';
          try {
            src = Buffer.from(this.mem.slice(a1, Math.min(a2, 96))).toString('hex');
          } catch {
            src = '<err>';
          }
          writeFileSync('d:/there/douyinhook/unidbg_work/tramp_ts.txt',
            `T fn=+0x${(fn - SO_BASE).toString(16)} a0=0x${a0.toString(16)} a1=0x${a1.toString(16)} ` +
              `a2=${a2} obj=0x${Number(cpu.x[19]).toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} src=${src}\n`,
            { flag: 'a' });
        }
      }
      if (dbgVmDump && cpu.pc === SO_BASE + 0x18a89c) {
        const x1 = Number(cpu.x[1]);
        const x4 = Number(cpu.x[4]);
        let off = Number(cpu.x[16]) & 0xffffffff;
        if (off & 0x80000000) off -= 0x100000000;
        if (x1 + off === 0xbfffde64) {
          const lines = [`pc=+0x18a898 x4=0x${x4.toString(16)} x1=0x${x1.toString(16)} ` +
            `off=${off} w15=0x${(Number(cpu.x[15]) & 0xffffffff).toString(16)}`];
          for (let i = 0; i < 0x60; i += 8) {
            lines.push(`  ctx+0x${i.toString(16)} = ${Buffer.from(this.mem.slice(x4 + i, 8)).toString('hex')}`);
          }
          writeFileSync('d:/there/douyinhook/unidbg_work/vmdump.txt', lines.join('\n') + '\n', { flag: 'a' });
        }
      }
      if (dbgVmSlot && cpu.pc === SO_BASE + 0x1822e4) {
        const x4 = Number(cpu.x[4]);
        const w10 = Number(cpu.x[10]) & 0xffffffff;
        const dst = (w10 >>> 17) & 0x1f;
        if (dst === 3) {
          const src = (w10 >>> 27) & 0x1f;
          const sh = (w10 >>> 22) & 0x1f;
          const sv = Number(this.mem.read(x4 + src * 8, 4)) >>> 0;
          writeFileSync('d:/there/douyinhook/unidbg_work/vmslot.txt',
            `w10=0x${w10.toString(16)} dst=${dst} src=${src} sh=${sh} slot=${sv.toString(16)} ` +
              `ctx=0x${x4.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}\n`, { flag: 'a' });
        }
      }
      if (dbgVmLoad && cpu.pc === SO_BASE + 0x1898d0) {
        const x1 = Number(cpu.x[1]) & 0xffffffff;
        if (x1 === 2) {
          const x4 = Number(cpu.x[4]);
          const base = Number(cpu.x[17]);
          const off = Number(cpu.x[0]) & 0xffffffff;
          let v = 0;
          try {
            v = Number(this.mem.read((base + off) >>> 0, 4)) >>> 0;
          } catch {
            v = 0xdead;
          }
          writeFileSync('d:/there/douyinhook/unidbg_work/vmload.txt',
            `slot=${x1} base=0x${base.toString(16)} off=0x${off.toString(16)} val=0x${v.toString(16)} ` +
              `ctx=0x${x4.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}\n`, { flag: 'a' });
        }
      }
      if (dbgLadon) {
        if (cpu.pc === SO_BASE + 0x275fb0) {
          const a0 = Number(cpu.x[0]);
          const a1 = Number(cpu.x[1]) & 0xffffffff;
          let dat = '';
          try {
            dat = Buffer.from(this.mem.slice(a0, Math.min(a1, 32))).toString('hex');
          } catch {
            dat = '<err>';
          }
          writeFileSync('d:/there/douyinhook/unidbg_work/ladon_ts.txt',
            `FN275FAC a0=0x${a0.toString(16)} a1=${a1} data=${dat} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}\n`,
            { flag: 'a' });
        }
        if (cpu.pc === SO_BASE + 0x188dd8) {
          const x16 = Number(cpu.x[16]);
          const w21 = Number(cpu.x[21]) & 0xffff;
          const off = w21 & 0x8000 ? w21 - 0x10000 : w21;
          const addr = (x16 + off) >>> 0;
          let v = 0n;
          try {
            v = this.mem.read(addr, 8);
          } catch {
            v = 0n;
          }
          if ((v >> 32n) === 0x934507fbn) {
            writeFileSync('d:/there/douyinhook/unidbg_work/ladon_ts.txt',
              `LD188 addr=0x${addr.toString(16)} v=0x${v.toString(16)} x16=0x${x16.toString(16)} off=0x${off.toString(16)}\n`,
              { flag: 'a' });
          }
        }
        if (cpu.pc === SO_BASE + 0x283adc) {
          const buf = Number(cpu.x[0]);
          const len = Number(cpu.x[1]) & 0xffffffff;
          let data = '';
          try {
            data = Buffer.from(this.mem.slice(buf, Math.min(len, 96))).toString('hex');
          } catch {
            data = '<err>';
          }
          writeFileSync('d:/there/douyinhook/unidbg_work/ladon_ts.txt',
            `HASH buf=0x${buf.toString(16)} len=${len} data=${data}\n`, { flag: 'a' });
        }
        if (cpu.pc === SO_BASE + 0x183ed8) {
          const x4 = Number(cpu.x[4]);
          const w10 = Number(cpu.x[10]) & 0xffffffff;
          const dst = w10 >>> 27;
          if (dst === 1) {
            const s1 = (w10 >>> 12) & 0x1f;
            const s2 = (w10 >>> 17) & 0x1f;
            const v1 = this.mem.read(x4 + s1 * 8, 8).toString(16);
            const v2 = this.mem.read(x4 + s2 * 8, 8).toString(16);
            let mem = '';
            const p2 = Number(this.mem.read(x4 + s2 * 8, 8) & 0xffffffffn);
            if (p2 >= 0x40000000 && p2 < 0x42000000) {
              try {
                mem = ` mem=${Buffer.from(this.mem.slice(p2, 48)).toString('hex')}`;
              } catch {
                mem = ' mem=<err>';
              }
            }
            writeFileSync('d:/there/douyinhook/unidbg_work/ladon_ts.txt',
              `XOR w10=0x${w10.toString(16)} s1=${s1}(0x${v1}) s2=${s2}(0x${v2}) ctx=0x${x4.toString(16)} ` +
                `lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}${mem}\n`, { flag: 'a' });
          }
        }
      }
      if (srcPc && cpu.pc === srcPc) {
        const n = Number(cpu.x[11]) & 0xffffffff;
        if (n >= 32) {
          const p = Number(cpu.x[23]);
          writeFileSync('d:/there/douyinhook/unidbg_work/srclog.txt',
            `len=${n} x23=0x${p.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} ` +
              `\t${this.mem.cstr(p).slice(0, 60)}\n`, { flag: 'a' });
        }
      }
      if (this.steps >= budget) {
        throw new Error(
          `冷启动指令预算耗尽 @0x${cpu.pc.toString(16)}\n` +
            `  最近指令: ${this.coldTailText()}`,
        );
      }
      this.coldTail[this.coldTailIdx] = cpu.pc;
      this.coldTailIdx = (this.coldTailIdx + 1) & 511;
      if (verbose) {
        const inLibc = cpu.pc >= 0x405b0000 && cpu.pc < 0x406c0000;
        if (inLibc !== this.coldInLibc) {
          console.log(`[cold] ${inLibc ? '进入' : '离开'} libc @0x${cpu.pc.toString(16)} ` +
            `lr=0x${Number(cpu.x[30]).toString(16)}`);
          this.coldInLibc = inLibc;
        }
      }
      try {
        cpu.step();
      } catch (e) {
        throw new Error(
          `冷启动异常 ${(e as Error).message} @pc=0x${cpu.pc.toString(16)} ` +
            `lr=0x${Number(cpu.x[30]).toString(16)} x0=0x${cpu.x[0].toString(16)}\n` +
            `  x8=0x${cpu.x[8].toString(16)} x19=0x${cpu.x[19].toString(16)} ` +
            `x20=0x${cpu.x[20].toString(16)} x21=0x${cpu.x[21].toString(16)} sp=0x${cpu.x[31].toString(16)}\n` +
            `  最近指令: ${this.coldTailText()}`,
        );
      }
      this.steps += 1;
      if (rwTargets) {
        for (let r = 1; r <= 5; r++) {
          const v = cpu.x[r];
          if (v !== rwPrev[r]) {
            rwPrev[r] = v;
            if (rwTargets.has(v.toString(16))) {
              writeFileSync('d:/there/douyinhook/unidbg_work/regwatch.txt',
                `pc=+0x${(cpu.pc - 4 - SO_BASE).toString(16)} x${r} <= 0x${v.toString(16)} ` +
                  `lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} sp=0x${cpu.x[31].toString(16)}\n`,
                { flag: 'a' });
            }
          }
        }
      }
    }
    return Number(cpu.x[0]);
  }

  /**
   * JIT 版 coldCall：按基本块翻译执行，语义与 coldCall 一致。
   * 仅在没有任何调试开关时走这里（调试路径仍用逐条解释，方便 dump）。
   */
  private coldCallJit(entry: number, args: number[], budget: number): number {
    const cpu = this.cpu;
    const xlo = cpu.xlo;
    const xhi = cpu.xhi;
    for (let i = 0; i <= 30; i++) {
      xlo[i] = 0;
      xhi[i] = 0;
    }
    for (let i = 0; i < args.length && i < 8; i++) {
      const v = args[i];
      xlo[i] = v | 0;
      xhi[i] = Math.floor(v / 4294967296) | 0;
    }
    xlo[30] = this.coldSentinel | 0;
    xhi[30] = 0;
    xlo[31] = this.coldSp | 0;
    xhi[31] = Math.floor(this.coldSp / 4294967296) | 0;
    cpu.pc = entry;
    cpu.tick = budget;
    this.steps = 0;
    this.coldTailIdx = 0;
    if (this.jit === null || this.jitHooks !== this.pcHooks.size) {
      const sk = process.env.SO_JITSKIP;
      const skip = sk
        ? new Set(sk.split(',').map((s) => Number(s.trim())).filter((n) => n > 0))
        : undefined;
      this.jit = new Jit(
        cpu, this.mem, this.coldSentinel, this.pcHooks, skip,
        SO_BASE, SO_BASE + this.coldMeta.extent,
      );
      this.jitHooks = this.pcHooks.size;
    }
    const jit = this.jit;
    const IDX = jit.idx;
    const LIST = jit.list;
    const HP = jit.hookPages;
    const LO = jit.codeLo;
    const SPAN = jit.codeHi - jit.codeLo;
    const hooks = this.pcHooks;
    // 热块阈值：同一块被遇到多少次才值得付 new Function 的编译成本
    const THRESH = this.jitThresh;
    let steps = 0;
    for (;;) {
      const pc = cpu.pc;
      if (pc === this.coldSentinel) break;
      const off = pc - LO;
      const inCode = off >>> 0 < SPAN;
      // 只有落在「有 hook 的页」才需要查 Map；区间外的 pc 一律查
      if (!inCode || HP[off >>> 16] !== 0) {
        const h = hooks.get(pc);
        if (h !== undefined && h(cpu)) continue;
      }
      if (steps >= budget) {
        this.steps = steps;
        throw new Error(`冷启动指令预算耗尽 @0x${pc.toString(16)}`);
      }
      let b = inCode ? LIST[IDX[off >>> 2] - 1] : jit.slowBlocks.get(pc);
      if (b === undefined) {
        // 未编译块先用解释器单步，遇到次数够了再编译（new Function 固定开销约 10µs）
        if (inCode) {
          const k = off >>> 2;
          const v = IDX[k];
          if (v === 0) {
            IDX[k] = -1;
            cpu.step();
            steps += 1;
            continue;
          }
          if (v > -THRESH) {
            IDX[k] = v - 1;
            cpu.step();
            steps += 1;
            continue;
          }
        }
        b = jit.compile(pc);
      }
      if (b.n === 0) {
        cpu.step();
        steps += 1;
        continue;
      }
      if (Jit.STAT) b.c = (b.c ?? 0) + 1;
      b.f(cpu);
      steps += b.n;
    }
    this.steps = steps;
    if (process.env.SO_JITSTAT) {
      let ins = 0;
      for (const x of LIST) ins += x.n;
      console.log(`[jit] blocks=${LIST.length} avg=${(ins / LIST.length).toFixed(1)} steps=${steps}`);
      for (const x of [...LIST].sort((a, b) => (b.c ?? 0) - (a.c ?? 0)).slice(0, 2)) {
        console.log(`--- calls=${x.c} n=${x.n}\n${(x.src ?? '').slice(0, 1500)}`);
      }
    }
    return xlo[0] >>> 0 === 0 && xhi[0] === 0 ? 0 : Number(cpu.x[0]);
  }

  /** 按 Java 侧 k3.callStaticJniMethodObject 的约定调用 native b */
  private coldB(op: number, a2: number, a3: number, a4: number, a5: number): number {
    if (op === 33554438) this.loadReplay();
    if (process.env.SO_MALLLOG && op === 33554438) {
      writeFileSync('d:/there/douyinhook/unidbg_work/malllog.txt', 'MARK sign\n', { flag: 'a' });
    }
    const r = this.coldCall(this.coldEntry, [this.coldEnv, this.coldClassHandle, op, a2, a3, a4, a5]);
    if (process.env.SO_STEPLOG) console.log(`[b] op=${op} steps=${this.steps} ret=0x${r.toString(16)}`);
    return r;
  }

  /** 指针是否指向合法的 JNINativeMethod 数组（首项的 name 指针可读且像标识符） */
  private methodsAt (ptr: number): boolean {
    try {
      const name = this.mem.cstr(Number(this.mem.read(ptr, 8)));
      return name.length > 0 && /^[A-Za-z_$]/.test(name);
    } catch {
      return false;
    }
  }

  private coldRegisterNatives(methods: number, count: number): void {
    const n = count & 0xffffffff;
    for (let i = 0; i < n; i++) {
      const p = methods + i * 24;
      const name = this.mem.cstr(Number(this.mem.read(p, 8)));
      const sig = this.mem.cstr(Number(this.mem.read(p + 8, 8)));
      const fn = Number(this.mem.read(p + 16, 8));
      this.coldNative.set(name, fn);
      if (this.verbose) console.log(`[native] ${name}${sig} @0x${fn.toString(16)}`);
    }
  }

  // ------------------------------------------------------------ libc 桩层

  /**
   * 冷启动不能执行真实 libc：bionic 的 dlmalloc / mem* 里用了 SIMD
   * （add v3.2d, v3.2d, v6.2d 之类），解释器不支持，也没必要支持。
   * 这里按导出符号地址打 pc 钩子，用 TS 等价实现。
   */
  private coldInstallLibHooks(): void {
    const hook = (name: string, fn: (cpu: Cpu) => void): void => {
      const addr = this.coldGlobals.get(name);
      if (process.env.SO_SYMLOG) {
        writeFileSync('d:/there/douyinhook/unidbg_work/symlog.txt',
          `${name} 0x${(addr ?? 0).toString(16)}\n`, { flag: 'a' });
      }
      if (addr) this.pcHooks.set(addr, (cpu) => { fn(cpu); return true; });
    };
    const A = (cpu: Cpu, i: number): number => Number(cpu.x[i]);
    const ret = (cpu: Cpu, v: number | bigint): void => {
      cpu.x[0] = BigInt.asUintN(64, BigInt(v));
      cpu.pc = Number(cpu.x[30]);
    };
    const ret32 = (cpu: Cpu, v: number): void => ret(cpu, BigInt.asUintN(32, BigInt(v)));
    const rd = (p: number, n: number): number => Number(this.mem.read(p, n));
    const wr = (p: number, n: number, v: number | bigint): void =>
      this.mem.write(p, n, BigInt.asUintN(n * 8, BigInt(v)));
    const cstr = (p: number): string => (p ? this.mem.cstr(p) : '');
    const slen = (p: number): number => {
      let n = 0;
      while (Number(this.mem.read(p + n, 1)) !== 0) n += 1;
      return n;
    };
    const scmp = (a: number, b: number, max: number): number => {
      for (let i = 0; i < max; i++) {
        const x = Number(this.mem.read(a + i, 1));
        const y = Number(this.mem.read(b + i, 1));
        if (x !== y) return x - y;
        if (x === 0) return 0;
      }
      return 0;
    };
    const writeStr = (dst: number, s: string, cap: number): number => {
      const b = Buffer.from(s, 'utf8');
      if (process.env.SO_FMTADDR && b.length >= 40) {
        writeFileSync('d:/there/douyinhook/unidbg_work/fmtaddr.txt',
          `dst=0x${dst.toString(16)} cap=${cap} len=${b.length}\t${s.slice(0, 60)}\n`, { flag: 'a' });
      }
      if (cap > 0) {
        const n = Math.min(b.length, cap - 1);
        if (n > 0) this.mem.load(dst, b.subarray(0, n));
        this.mem.write(dst + n, 1, 0n);
      }
      return b.length;
    };

    // ---- malloc 家族（bump 分配，free 不回收）----
    const dMallLog = !!process.env.SO_MALLLOG;
    const mallLog = (name: string, n: number, p: number): void => {
      if (!dMallLog) return;
      let extra = '';
      if (n === 48) {
        const sp = Number(this.cpu.x[31]);
        try {
          extra = ` caller=0x${Number(this.mem.read(sp + 8, 8)).toString(16)}`;
        } catch {
          extra = ' caller=<err>';
        }
      }
      writeFileSync('d:/there/douyinhook/unidbg_work/malllog.txt',
        `${name} n=${n} ret=0x${p.toString(16)} lr=0x${Number(this.cpu.x[30]).toString(16)}${extra}\n`,
        { flag: 'a' });
    };
    hook('malloc', (cpu) => {
      const n = A(cpu, 0) || 1;
      const p = (this.replayOn && this.replayAlloc('malloc', n)) || this.coldAlloc(n);
      mallLog('malloc', n, p);
      ret(cpu, p);
    });
    hook('calloc', (cpu) => {
      const n = (A(cpu, 0) * A(cpu, 1)) || 1;
      const p = (this.replayOn && this.replayAlloc('calloc', n)) || this.coldAlloc(n);
      mallLog('calloc', n, p);
      ret(cpu, p);
    });
    hook('realloc', (cpu) => {
      const p = A(cpu, 0);
      const n = A(cpu, 1);
      if (!p) { ret(cpu, this.coldAlloc(n || 1)); return; }
      if (!n) { this.coldAllocs.delete(p); ret(cpu, 0); return; }
      const oldSize = this.coldAllocs.get(p) ?? 0;
      const q = (this.replayOn && this.replayAlloc('realloc', n)) || this.coldAlloc(n);
      const k = Math.min(oldSize, n);
      if (k > 0 && q !== p) this.mem.copy(q, p, k);
      if (q !== p) this.coldAllocs.delete(p);
      this.coldAllocs.set(q, n);
      ret(cpu, q);
    });
    hook('free', (cpu) => { this.coldAllocs.delete(A(cpu, 0)); ret(cpu, 0); });
    hook('posix_memalign', (cpu) => {
      const pp = A(cpu, 0);
      const align = A(cpu, 1);
      const n = A(cpu, 2);
      let q = this.coldAlloc(n);
      if (align > 16) q = (q + align - 1) & ~(align - 1);
      this.coldAllocs.set(q, n);
      wr(pp, 8, q);
      ret32(cpu, 0);
    });

    // ---- mem* ----
    const dMemLog = !!process.env.SO_MEMLOG;
    const dFrameLog = !!process.env.SO_FRAMELOG;
    const dLdrbLog = !!process.env.SO_LDRBLOG;
    const dRfLog = !!process.env.SO_RFLOG;
    const dWLog = !!process.env.SO_WLOG;
    const dS2Dump = !!process.env.SO_S2DUMP;
    const dDumpCp = process.env.SO_DUMPCP ? Number.parseInt(process.env.SO_DUMPCP, 16) : -1;
    const doMemcpy = (cpu: Cpu): void => {
      const dst = A(cpu, 0);
      const n = A(cpu, 2);
      if (dMemLog && n >= 16 && dst >= 0x50000000 && dst < 0x50100000) {
        const src = A(cpu, 1);
        writeFileSync('d:/there/douyinhook/unidbg_work/memlog.txt',
          `dst=0x${dst.toString(16)} src=0x${src.toString(16)} n=${n} lr=+0x${(Number(cpu.x[30]) - this.base).toString(16)} ` +
            `src=${Buffer.from(this.mem.slice(src, Math.min(n, 32))).toString('hex')}\n`, { flag: 'a' });
      }
      if (dFrameLog && dst === 0x407bf06b) {
        writeFileSync('d:/there/douyinhook/unidbg_work/frame_ts.txt', this.ctxTrace.join('\n') + '\n');
        this.mem.watch = null;
        process.env.SO_FRAMELOG = '';
      }
      if (dLdrbLog && dst === 0x407bf06b) {
        writeFileSync('d:/there/douyinhook/unidbg_work/ldrb_ts.txt', this.ldrbLog.join('\n') + '\n');
        process.env.SO_LDRBLOG = '';
      }
      if (dRfLog && dst === 0x407bfc00) {
        writeFileSync('d:/there/douyinhook/unidbg_work/rf2_ts.txt', this.rfLog.join('\n') + '\n');
        this.mem.watch = null;
        this.mem.watch2 = null;
        this.mem.watch3 = null;
        process.env.SO_RFLOG = '';
      }
      if (dWLog) {
        const src = A(cpu, 1);
        this.wlog.push(`C ${(Number(cpu.x[30]) - SO_BASE).toString(16)} ${dst.toString(16)} ${src.toString(16)} ${n} ` +
          `${Buffer.from(this.mem.slice(src, n)).toString('hex')}`);
      }
      if (dS2Dump && dst === 0x407bfc00) {
        // S2 输出区在拷贝前 dump（源区 0x407bf800 不被本次拷贝改动）
        writeFileSync('d:/there/douyinhook/unidbg_work/s2_ts.txt',
          Buffer.from(this.mem.slice(0x407bf800, 0x324)).toString('hex') + '\n');
        if (dWLog) {
          writeFileSync('d:/there/douyinhook/unidbg_work/wlog_ts.txt', this.wlog.join('\n') + '\n');
        }
        process.env.SO_S2DUMP = '';
      }
      if (dDumpCp >= 0) {
        const dstWant = dDumpCp;
        if (dst === dstWant) {
          const src = A(cpu, 1);
          writeFileSync(`d:/there/douyinhook/unidbg_work/cp_ts_${dstWant.toString(16)}.txt`,
            Buffer.from(this.mem.slice(src, n)).toString('hex') + '\n');
        }
      }
      if (n > 0) this.mem.copy(dst, A(cpu, 1), n);
      if (process.env.SO_BBLOG && dst >= 0x407bf000 && dst < 0x407c0000) {
        const src = A(cpu, 1);
        this.bbWrites.push(
          `memcpy dst=0x${dst.toString(16)} src=0x${src.toString(16)} n=${n} ` +
            `lr=+0x${(Number(cpu.x[30]) - this.base).toString(16)} ` +
            `data=${Buffer.from(this.mem.slice(src, Math.min(n, 40))).toString('hex')}`);
      }
      ret(cpu, dst);
    };
    for (const n of ['memcpy', '__memcpy_chk', 'memmove', '__memmove_chk']) hook(n, doMemcpy);
    const doMemset = (cpu: Cpu): void => {
      const dst = A(cpu, 0);
      const n = A(cpu, 2);
      if (dWLog) {
        this.wlog.push(`F ${(Number(cpu.x[30]) - SO_BASE).toString(16)} ${dst.toString(16)} ${A(cpu, 1).toString(16)} ${n}`);
      }
      if (n > 0) this.mem.fill(dst, A(cpu, 1), n);
      ret(cpu, dst);
    };
    for (const n of ['memset', '__memset_chk']) hook(n, doMemset);
    hook('memcmp', (cpu) => {
      const a = A(cpu, 0);
      const b = A(cpu, 1);
      const n = A(cpu, 2);
      let r = 0;
      for (let i = 0; i < n; i++) {
        const x = Number(this.mem.read(a + i, 1));
        const y = Number(this.mem.read(b + i, 1));
        if (x !== y) { r = x - y; break; }
      }
      ret32(cpu, r);
    });
    hook('memchr', (cpu) => {
      const p = A(cpu, 0);
      const c = A(cpu, 1) & 0xff;
      const n = A(cpu, 2);
      let r = 0;
      for (let i = 0; i < n; i++) {
        if (Number(this.mem.read(p + i, 1)) === c) { r = p + i; break; }
      }
      ret(cpu, r);
    });

    // ---- str* ----
    for (const n of ['strlen', '__strlen_chk']) hook(n, (cpu) => ret(cpu, slen(A(cpu, 0))));
    hook('strcmp', (cpu) => ret32(cpu, scmp(A(cpu, 0), A(cpu, 1), Infinity)));
    hook('strncmp', (cpu) => ret32(cpu, scmp(A(cpu, 0), A(cpu, 1), A(cpu, 2))));
    hook('strcpy', (cpu) => {
      const dst = A(cpu, 0);
      this.mem.copy(dst, A(cpu, 1), slen(A(cpu, 1)) + 1);
      ret(cpu, dst);
    });
    hook('strncpy', (cpu) => {
      const dst = A(cpu, 0);
      const src = A(cpu, 1);
      const n = A(cpu, 2);
      let i = 0;
      for (; i < n; i++) {
        const c = Number(this.mem.read(src + i, 1));
        this.mem.write(dst + i, 1, BigInt(c));
        if (c === 0) break;
      }
      for (i += 1; i < n; i++) this.mem.write(dst + i, 1, 0n);
      ret(cpu, dst);
    });
    const doStrdup = (cpu: Cpu, max: number): void => {
      const src = A(cpu, 0);
      const n = Math.min(slen(src), max);
      const q = this.coldAlloc(n + 1);
      if (n > 0) this.mem.copy(q, src, n);
      this.mem.write(q + n, 1, 0n);
      ret(cpu, q);
    };
    hook('strdup', (cpu) => doStrdup(cpu, Infinity));
    hook('strndup', (cpu) => doStrdup(cpu, A(cpu, 1)));
    hook('strstr', (cpu) => {
      const p = A(cpu, 0);
      const h = cstr(p);
      const i = h.indexOf(cstr(A(cpu, 1)));
      ret(cpu, i < 0 ? 0 : p + Buffer.byteLength(h.slice(0, i)));
    });
    hook('strcasestr', (cpu) => {
      const p = A(cpu, 0);
      const h = cstr(p).toLowerCase();
      const i = h.indexOf(cstr(A(cpu, 1)).toLowerCase());
      ret(cpu, i < 0 ? 0 : p + Buffer.byteLength(h.slice(0, i)));
    });
    hook('strrchr', (cpu) => {
      const p = A(cpu, 0);
      const c = A(cpu, 1) & 0xff;
      let last = 0;
      for (let i = 0; ; i++) {
        const b = Number(this.mem.read(p + i, 1));
        if (b === c) last = p + i;
        if (b === 0) break;
      }
      ret(cpu, last);
    });
    hook('strcspn', (cpu) => {
      const s = A(cpu, 0);
      const rej = A(cpu, 1);
      let n = 0;
      outer: for (;;) {
        const b = Number(this.mem.read(s + n, 1));
        if (b === 0) break;
        for (let k = 0; ; k++) {
          const d = Number(this.mem.read(rej + k, 1));
          if (d === 0) break;
          if (d === b) break outer;
        }
        n += 1;
      }
      ret(cpu, n);
    });

    // ---- 数字解析 ----
    const parseInt10 = (p: number): number => {
      let i = 0;
      const b = (k: number): number => Number(this.mem.read(p + k, 1));
      while (b(i) === 0x20 || (b(i) >= 9 && b(i) <= 13)) i += 1;
      let neg = false;
      if (b(i) === 0x2d) { neg = true; i += 1; } else if (b(i) === 0x2b) i += 1;
      let v = 0;
      for (;;) {
        const c = b(i);
        if (c < 0x30 || c > 0x39) break;
        v = v * 10 + (c - 0x30);
        i += 1;
      }
      return neg ? -v : v;
    };
    hook('atoi', (cpu) => ret32(cpu, parseInt10(A(cpu, 0))));
    hook('atoll', (cpu) => ret(cpu, BigInt(parseInt10(A(cpu, 0)))));
    const strToInt = (p: number, base: number, signed: boolean): [bigint, number] => {
      const b = (k: number): number => Number(this.mem.read(p + k, 1));
      let i = 0;
      while (b(i) === 0x20 || (b(i) >= 9 && b(i) <= 13)) i += 1;
      let neg = false;
      if (b(i) === 0x2d) { neg = true; i += 1; } else if (b(i) === 0x2b) i += 1;
      let radix = base;
      if ((radix === 0 || radix === 16) && b(i) === 0x30 && (b(i + 1) | 0x20) === 0x78) {
        radix = 16;
        i += 2;
      } else if (radix === 0) {
        radix = b(i) === 0x30 ? 8 : 10;
      }
      const big = BigInt(radix);
      let v = 0n;
      for (;;) {
        const c = b(i);
        let d = -1;
        if (c >= 0x30 && c <= 0x39) d = c - 0x30;
        else if (c >= 0x61 && c <= 0x7a) d = c - 0x61 + 10;
        else if (c >= 0x41 && c <= 0x5a) d = c - 0x41 + 10;
        if (d < 0 || d >= radix) break;
        v = v * big + BigInt(d);
        i += 1;
      }
      if (neg) v = -v;
      return [signed ? BigInt.asIntN(64, v) : BigInt.asUintN(64, v), p + i];
    };
    const doStrTo = (cpu: Cpu, signed: boolean): void => {
      const [v, end] = strToInt(A(cpu, 0), A(cpu, 2), signed);
      const ep = A(cpu, 1);
      if (ep) wr(ep, 8, end);
      ret(cpu, v);
    };
    for (const n of ['strtol', 'strtoll', 'strtoimax']) hook(n, (cpu) => doStrTo(cpu, true));
    hook('strtoull', (cpu) => doStrTo(cpu, false));
    hook('strtod', (cpu) => {
      const p = A(cpu, 0);
      const s = cstr(p);
      const m = /^\s*[-+]?(\d+\.?\d*([eE][-+]?\d+)?|\.\d+([eE][-+]?\d+)?)/.exec(s);
      const ep = A(cpu, 1);
      if (ep) wr(ep, 8, p + (m ? Buffer.byteLength(m[0]) : 0));
      const dv = new DataView(new ArrayBuffer(8));
      dv.setFloat64(0, m ? Number(m[0]) : 0, true);
      ret(cpu, dv.getBigUint64(0, true));
    });
    const strtokSave = this.coldAlloc(8);
    const strtokR = (s: number, delim: number, save: number): number => {
      const isDelim = (c: number): boolean => {
        for (let k = 0; ; k++) {
          const d = Number(this.mem.read(delim + k, 1));
          if (d === 0) return false;
          if (d === c) return true;
        }
      };
      let p = s !== 0 ? s : rd(save, 8);
      if (!p) return 0;
      while (Number(this.mem.read(p, 1)) !== 0 && isDelim(Number(this.mem.read(p, 1)))) p += 1;
      if (Number(this.mem.read(p, 1)) === 0) { wr(save, 8, 0); return 0; }
      const start = p;
      while (Number(this.mem.read(p, 1)) !== 0 && !isDelim(Number(this.mem.read(p, 1)))) p += 1;
      if (Number(this.mem.read(p, 1)) === 0) wr(save, 8, 0);
      else { this.mem.write(p, 1, 0n); wr(save, 8, p + 1); }
      return start;
    };
    hook('strtok_r', (cpu) => ret(cpu, strtokR(A(cpu, 0), A(cpu, 1), A(cpu, 2))));
    hook('strtok', (cpu) => ret(cpu, strtokR(A(cpu, 0), A(cpu, 1), strtokSave)));

    // ---- pthread ----
    for (const n of [
      'pthread_mutex_init', 'pthread_mutex_destroy', 'pthread_mutex_lock', 'pthread_mutex_trylock',
      'pthread_mutex_unlock', 'pthread_mutexattr_init', 'pthread_mutexattr_destroy',
      'pthread_mutexattr_settype', 'pthread_cond_init', 'pthread_cond_destroy',
      'pthread_cond_signal', 'pthread_cond_broadcast', 'pthread_cond_wait',
      'pthread_cond_timedwait', 'pthread_rwlock_rdlock', 'pthread_rwlock_wrlock',
      'pthread_rwlock_unlock', 'pthread_detach', 'pthread_join',
    ]) hook(n, (cpu) => ret32(cpu, 0));
    hook('pthread_self', (cpu) => ret(cpu, cpu.tpidr));
    hook('pthread_create', (cpu) => {
      const tp = A(cpu, 0);
      // 单线程解释器无法真跑新线程；只回填线程 id，否则后台线程会死循环
      if (tp) wr(tp, 8, cpu.tpidr);
      ret32(cpu, 0);
    });
    hook('pthread_key_create', (cpu) => {
      const p = A(cpu, 0);
      const key = this.coldKeySeq;
      this.coldKeySeq += 1;
      if (p) wr(p, 4, key);
      ret32(cpu, 0);
    });
    hook('pthread_key_delete', (cpu) => { this.coldTls.delete(A(cpu, 0)); ret32(cpu, 0); });
    hook('pthread_getspecific', (cpu) => ret(cpu, this.coldTls.get(A(cpu, 0)) ?? 0));
    hook('pthread_setspecific', (cpu) => {
      this.coldTls.set(A(cpu, 0), A(cpu, 1));
      ret32(cpu, 0);
    });
    hook('pthread_once', (cpu) => {
      const p = A(cpu, 0);
      const fn = A(cpu, 1);
      if (rd(p, 4) === 0) {
        wr(p, 4, 1);
        if (fn) this.coldInvoke(fn, []);
      }
      ret32(cpu, 0);
    });

    // ---- stdio / 格式化 ----
    hook('printf', (cpu) => {
      const s = this.coldVFormat(cstr(A(cpu, 0)), this.coldRegArgs(cpu, 1));
      if (this.verbose) console.log(`[libc] ${s}`);
      ret32(cpu, s.length);
    });
    hook('fprintf', (cpu) => {
      const s = this.coldVFormat(cstr(A(cpu, 1)), this.coldRegArgs(cpu, 2));
      if (this.verbose) console.log(`[libc] ${s}`);
      ret32(cpu, s.length);
    });
    hook('vfprintf', (cpu) => {
      const s = this.coldVFormat(cstr(A(cpu, 1)), new VaList(this.mem, A(cpu, 2), ''));
      if (this.verbose) console.log(`[libc] ${s}`);
      ret32(cpu, s.length);
    });
    hook('vsnprintf', (cpu) => {
      const va = A(cpu, 3);
      if (process.env.SO_FMTLOG && cstr(A(cpu, 2)).includes('llu')) {
        const raw = Buffer.from(this.mem.slice(va, 32)).toString('hex');
        const grTop = Number(this.mem.read(va + 8, 8));
        let grOff = s32(Number(this.mem.read(va + 24, 4)));
        const vals: string[] = [];
        for (let i = 0; i < 5; i++) {
          const a = Number(this.mem.read(grTop + grOff, 8));
          grOff += 8;
          vals.push(`0x${a.toString(16)}`);
        }
        const ptr = Number(this.mem.read(grTop + s32(Number(this.mem.read(va + 24, 4))) + 32, 8));
        const mem5 = Buffer.from(this.mem.slice(ptr, 48)).toString('hex');
        writeFileSync('d:/there/douyinhook/unidbg_work/fmtlog.txt',
          `va=0x${va.toString(16)} raw=${raw} args=${vals.join(',')} mem5=${mem5}\n`, { flag: 'a' });
      }
      const s = this.coldVFormat(cstr(A(cpu, 2)), new VaList(this.mem, va, ''));
      ret32(cpu, writeStr(A(cpu, 0), s, A(cpu, 1)));
    });
    hook('__vsnprintf_chk', (cpu) => {
      const s = this.coldVFormat(cstr(A(cpu, 4)), new VaList(this.mem, A(cpu, 5), ''));
      ret32(cpu, writeStr(A(cpu, 0), s, A(cpu, 1)));
    });
    hook('__vsprintf_chk', (cpu) => {
      const s = this.coldVFormat(cstr(A(cpu, 3)), new VaList(this.mem, A(cpu, 4), ''));
      ret32(cpu, writeStr(A(cpu, 0), s, A(cpu, 2)));
    });
    const doAsprintf = (cpu: Cpu, strp: number, s: string): void => {
      const b = Buffer.from(s, 'utf8');
      const q = this.coldAlloc(b.length + 1);
      if (b.length) this.mem.load(q, b);
      this.mem.write(q + b.length, 1, 0n);
      wr(strp, 8, q);
      ret32(cpu, b.length);
    };
    hook('asprintf', (cpu) => {
      doAsprintf(cpu, A(cpu, 0), this.coldVFormat(cstr(A(cpu, 1)), this.coldRegArgs(cpu, 2)));
    });
    hook('vasprintf', (cpu) => {
      doAsprintf(cpu, A(cpu, 0), this.coldVFormat(cstr(A(cpu, 1)), new VaList(this.mem, A(cpu, 2), '')));
    });
    hook('fwrite', (cpu) => ret32(cpu, A(cpu, 2)));
    hook('fputc', (cpu) => ret32(cpu, A(cpu, 0)));
    hook('fflush', (cpu) => ret32(cpu, 0));
    hook('fopen', (cpu) => {
      const path = cstr(A(cpu, 0));
      const fd = this.sysOpen(path);
      if (this.verbose) console.log(`[libc] fopen(${JSON.stringify(path)}) => fd ${fd}`);
      if (fd < 0) { ret(cpu, 0); return; }
      const h = 0x6c000000 + fd;
      this.coldFiles.set(h, fd);
      ret(cpu, h);
    });
    hook('fread', (cpu) => {
      const size = A(cpu, 1);
      const n = A(cpu, 2);
      const fd = this.coldFiles.get(A(cpu, 3));
      if (fd === undefined) { ret(cpu, 0); return; }
      const got = Math.max(0, this.sysRead(fd, A(cpu, 0), size * n));
      ret(cpu, size > 0 ? Math.floor(got / size) : 0);
    });
    hook('fclose', (cpu) => {
      const h = A(cpu, 0);
      const fd = this.coldFiles.get(h);
      if (fd !== undefined) { this.coldFiles.delete(h); this.fds.delete(fd); }
      ret32(cpu, 0);
    });
    hook('sscanf', (cpu) => ret32(cpu, 0));
    hook('strerror_r', (cpu) => {
      writeStr(A(cpu, 1), `errno ${A(cpu, 0)}`, A(cpu, 2));
      ret32(cpu, 0);
    });

    // ---- 进程 / 文件 / 网络 ----
    hook('getpid', (cpu) => ret32(cpu, this.pid));
    hook('getppid', (cpu) => ret32(cpu, this.pid));
    hook('gettid', (cpu) => ret32(cpu, this.pid));
    hook('getuid', (cpu) => ret32(cpu, 0));
    hook('getpagesize', (cpu) => ret32(cpu, 4096));
    hook('sysconf', (cpu) => {
      const k = A(cpu, 0);
      ret32(cpu, k === 39 ? 4096 : (k === 96 || k === 97 ? 8 : 0));
    });
    hook('getenv', (cpu) => ret(cpu, 0));
    hook('__errno', (cpu) => ret(cpu, Number(cpu.tpidr) + 0x10));
    hook('__system_property_find', (cpu) => ret(cpu, 0));
    hook('__system_property_get', (cpu) => {
      const v = A(cpu, 1);
      if (v) this.mem.write(v, 1, 0n);
      ret32(cpu, 0);
    });
    hook('__system_property_read', (cpu) => ret32(cpu, 0));
    hook('__open_2', (cpu) => {
      const path = cstr(A(cpu, 0));
      const fd = this.sysOpen(path);
      if (this.verbose) console.log(`[libc] open(${JSON.stringify(path)}) => ${fd}`);
      ret32(cpu, fd);
    });
    hook('read', (cpu) => ret(cpu, BigInt.asUintN(64, BigInt(this.sysRead(A(cpu, 0), A(cpu, 1), A(cpu, 2))))));
    hook('__read_chk', (cpu) => ret(cpu, BigInt.asUintN(64, BigInt(this.sysRead(A(cpu, 0), A(cpu, 1), A(cpu, 2))))));
    hook('close', (cpu) => { this.fds.delete(A(cpu, 0)); ret32(cpu, 0); });
    hook('fstat', (cpu) => { this.sysFstat(A(cpu, 0), A(cpu, 1)); ret32(cpu, 0); });
    hook('mmap', (cpu) => ret(cpu, this.coldMmap(A(cpu, 0), A(cpu, 1))));
    hook('munmap', (cpu) => ret32(cpu, 0));
    hook('mprotect', (cpu) => ret32(cpu, 0));
    hook('uname', (cpu) => {
      if (A(cpu, 0)) this.mem.load(A(cpu, 0), new Uint8Array(390));
      ret32(cpu, 0);
    });
    hook('sysinfo', (cpu) => {
      if (A(cpu, 0)) this.mem.load(A(cpu, 0), new Uint8Array(112));
      ret32(cpu, 0);
    });
    hook('syscall', (cpu) => {
      const nr = A(cpu, 0);
      for (let i = 0; i < 6; i++) cpu.x[i] = cpu.x[i + 1];
      cpu.x[8] = BigInt(nr);
      this.coldSyscall(cpu, nr);
      cpu.pc = Number(cpu.x[30]);
    });
    for (const n of [
      'access', 'stat', 'lstat', 'fstatat', 'mkdir', 'unlink', 'remove', 'readlink',
      'ioctl', 'socket', 'bind', 'connect', 'sendto', 'recvfrom', 'setsockopt', 'inet_addr',
      'fork', 'system',
    ]) hook(n, (cpu) => ret32(cpu, -1));
    for (const n of ['opendir', 'readdir', 'popen']) hook(n, (cpu) => ret(cpu, 0));
    for (const n of [
      '__cxa_atexit', '__cxa_finalize', '__cxa_thread_atexit_impl', 'kill', 'sigaction',
      'sigprocmask', 'sigaddset', 'sigemptyset', 'prctl', 'getauxval', 'openlog', 'closelog',
      'syslog', 'android_set_abort_message', 'closedir', 'dlclose', 'dl_iterate_phdr',
    ]) hook(n, (cpu) => ret32(cpu, 0));

    // ---- 动态链接 ----
    hook('dlopen', (cpu) => ret(cpu, 0x6b000001));
    hook('dlsym', (cpu) => ret(cpu, this.coldGlobals.get(cstr(A(cpu, 1))) ?? 0));

    // ---- 致命错误：直接抛出，便于定位 ----
    hook('__stack_chk_fail', () => { throw new Error('__stack_chk_fail：栈保护被触发'); });
    hook('abort', () => { throw new Error('abort()'); });
  }

  /** 签名阶段：按 oracle dlmalloc 序列回放地址（返回 0 表示未命中） */
  private replayAlloc(name: string, n: number): number {
    const list = this.replayList;
    const eq = (i: number): boolean => i < list.length && list[i].name === name && list[i].n === n;
    let j = -1;
    if (eq(this.replayIdx)) j = this.replayIdx;
    else if (eq(this.replayIdx + 1)) {
      // 当前条目是 TS 没做的分配（如 libc 内部 malloc），跳过
      if (process.env.SO_MALLLOG) {
        writeFileSync('d:/there/douyinhook/unidbg_work/malllog.txt',
          `SKIP ${list[this.replayIdx].name} n=${list[this.replayIdx].n} idx=${this.replayIdx}\n`, { flag: 'a' });
      }
      j = this.replayIdx + 1;
    }
    if (j < 0) return 0;
    this.replayIdx = j + 1;
    const p = list[j].addr;
    this.coldAllocs.set(p, n);
    if (name === 'calloc') this.mem.fill(p, 0, n);
    if (process.env.SO_MALLLOG) {
      writeFileSync('d:/there/douyinhook/unidbg_work/malllog.txt',
        `HIT ${name} n=${n} idx=${j} ret=0x${p.toString(16)}\n`, { flag: 'a' });
    }
    return p;
  }

  /** 载入 dlmalloc 分配序列（内嵌常量；SO_REPLAY 可覆盖为 alloc_or.txt 原始日志） */
  private loadReplay(): void {
    if (this.replayList.length) return;
    const path = process.env.SO_REPLAY;
    const txt = path ? readFileSync(path, 'utf8') : ALLOC_REPLAY;
    const re = path ? /^(\w+) n=(\d+) ret=0x([0-9a-f]+)/ : /^(\w+) (\d+) ([0-9a-f]+)/;
    for (const line of txt.split(/\r?\n/)) {
      const m = re.exec(line);
      if (m) this.replayList.push({ name: m[1], n: Number(m[2]), addr: parseInt(m[3], 16) });
    }
    this.replayOn = this.replayList.length > 0;
  }

  /** bump 分配（页已在 loadCold 里预映射，内容天然为 0） */
  private coldAlloc(n: number): number {
    const size = Math.max(16, (n + 15) & ~15);
    const p = this.coldHeap;
    if (p + size > 0x56000000) throw new Error('冷启动堆耗尽');
    this.coldHeap = p + size;
    this.coldAllocs.set(p, n);
    if (process.env.SO_ALLOCLOG) {
      writeFileSync('d:/there/douyinhook/unidbg_work/alloclog.txt',
        `0x${p.toString(16)} n=${n} lr=${(Number(this.cpu.x[30]) - SO_BASE).toString(16)}\n`, { flag: 'a' });
    }
    return p;
  }

  /** 嵌套调用 so 函数（pthread_once 等回调），保存/恢复全部现场 */
  private coldInvoke(entry: number, args: number[], budget = this.maxSteps): number {
    const cpu = this.cpu;
    const st = cpu.saveRegs();
    const nzcv = cpu.nzcv;
    const pc = cpu.pc;
    const tick = cpu.tick;
    const depth = this.coldDepth + 1;
    this.coldDepth = depth;
    for (let i = 0; i <= 30; i++) cpu.x[i] = 0n;
    for (let i = 0; i < args.length && i < 8; i++) cpu.x[i] = BigInt.asUintN(64, BigInt(args[i]));
    cpu.x[30] = BigInt(this.coldSentinel);
    cpu.x[31] = BigInt(this.coldSp - depth * 0x8000);
    cpu.pc = entry;
    cpu.tick = budget;
    let n = 0;
    try {
      for (;;) {
        if (cpu.pc === this.coldSentinel) break;
        const h = this.pcHooks.get(cpu.pc);
        if (h && h(cpu)) continue;
        if (n >= budget) throw new Error(`冷启动嵌套调用预算耗尽 @0x${cpu.pc.toString(16)}`);
        cpu.step();
        n += 1;
        this.steps += 1;
      }
      return Number(cpu.x[0]);
    } finally {
      cpu.restoreRegs(st);
      cpu.nzcv = nzcv;
      cpu.pc = pc;
      cpu.tick = tick;
      this.coldDepth = depth - 1;
    }
  }

  /** asprintf/printf 的取参：x<start..7> 然后栈 */
  private coldRegArgs(cpu: Cpu, start: number): ArgSrc {
    let gi = start;
    let fi = 0;
    let sp = Number(cpu.x[31]);
    const dv = new DataView(new ArrayBuffer(8));
    return {
      int: (size: number): number => {
        let v: number;
        if (gi < 8) {
          v = Number(cpu.x[gi]);
          gi += 1;
        } else {
          v = Number(this.mem.read(sp, 8));
          sp += 8;
        }
        return size === 8 ? v : v >>> 0;
      },
      fp: (): number => {
        if (fi < 8) {
          dv.setBigUint64(0, cpu.v[2 * fi], true);
          fi += 1;
        } else {
          dv.setBigUint64(0, this.mem.read(sp, 8), true);
          sp += 8;
        }
        return dv.getFloat64(0, true);
      },
    };
  }

  /** 最小 printf 格式化：%d %i %u %x %X %o %c %s %p %f %e %g %% + 宽度/精度/标志 */
  private coldVFormat(fmt: string, a: ArgSrc): string {
    const out: string[] = [];
    for (let i = 0; i < fmt.length; i++) {
      const ch = fmt[i];
      if (ch !== '%') { out.push(ch); continue; }
      let j = i + 1;
      if (fmt[j] === '%') { out.push('%'); i = j; continue; }
      let flags = '';
      while (j < fmt.length && '-+ #0'.includes(fmt[j])) { flags += fmt[j]; j += 1; }
      let width = 0;
      if (fmt[j] === '*') {
        width = a.int(4) | 0;
        j += 1;
        if (width < 0) { flags += '-'; width = -width; }
      } else {
        while (fmt[j] >= '0' && fmt[j] <= '9') { width = width * 10 + fmt.charCodeAt(j) - 48; j += 1; }
      }
      let prec = -1;
      if (fmt[j] === '.') {
        j += 1;
        prec = 0;
        if (fmt[j] === '*') { prec = a.int(4) | 0; j += 1; }
        else while (fmt[j] >= '0' && fmt[j] <= '9') { prec = prec * 10 + fmt.charCodeAt(j) - 48; j += 1; }
      }
      let len = '';
      while (j < fmt.length && 'hljztL'.includes(fmt[j])) { len += fmt[j]; j += 1; }
      const conv = fmt[j] ?? '';
      i = j;
      const wide = len === 'l' || len === 'll' || len === 'j' || len === 'z' || len === 't';
      let s: string;
      let negative = false;
      switch (conv) {
        case 'd':
        case 'i': {
          const raw = wide ? BigInt.asIntN(64, BigInt(a.int(8))) : BigInt(a.int(4) | 0);
          negative = raw < 0n;
          s = (negative ? -raw : raw).toString(10);
          break;
        }
        case 'u':
          s = (wide ? BigInt.asUintN(64, BigInt(a.int(8))) : BigInt(a.int(4) >>> 0)).toString(10);
          break;
        case 'x':
        case 'X':
        case 'o': {
          const v = wide ? BigInt.asUintN(64, BigInt(a.int(8))) : BigInt(a.int(4) >>> 0);
          s = v.toString(conv === 'o' ? 8 : 16);
          if (conv === 'X') s = s.toUpperCase();
          if (flags.includes('#')) s = (conv === 'o' ? '0' : (conv === 'x' ? '0x' : '0X')) + s;
          break;
        }
        case 'p': {
          const p = a.int(8);
          s = '0x' + p.toString(16);
          break;
        }
        case 'c':
          s = String.fromCharCode(a.int(4) & 0xff);
          break;
        case 's': {
          const p = a.int(8);
          s = p ? this.mem.cstr(p) : '(null)';
          if (prec >= 0) s = s.slice(0, prec);
          break;
        }
        case 'f':
        case 'F':
        case 'e':
        case 'E':
        case 'g':
        case 'G': {
          const d = a.fp();
          s = conv === 'f' || conv === 'F' ? d.toFixed(prec >= 0 ? prec : 6) : String(d);
          if (conv === 'E' || conv === 'G') s = s.toUpperCase();
          if (s.startsWith('-')) { negative = true; s = s.slice(1); }
          break;
        }
        default:
          s = '%' + conv;
      }
      if (prec >= 0 && 'diuxXo'.includes(conv)) while (s.length < prec) s = '0' + s;
      const sign = negative ? '-' : (flags.includes('+') && 'di'.includes(conv) ? '+'
        : (flags.includes(' ') && 'di'.includes(conv) ? ' ' : ''));
      let body = sign + s;
      if (width > body.length) {
        const pad = width - body.length;
        if (flags.includes('-')) body += ' '.repeat(pad);
        else if (flags.includes('0') && prec < 0) body = sign + '0'.repeat(pad) + s;
        else body = ' '.repeat(pad) + body;
      }
      out.push(body);
    }
    const res = out.join('');
    if (process.env.SO_FMTLOG && res.length) {
      const pc = this.cpu ? this.cpu.pc - SO_BASE : 0;
      const lr = this.cpu ? Number(this.cpu.x[30]) - SO_BASE : 0;
      let frames = '';
      if (fmt.includes('llu') && this.cpu) {
        const fs: string[] = [];
        let fp = Number(this.cpu.x[29]);
        for (let k = 0; k < 10 && fp; k++) {
          const prev = Number(this.mem.read(fp, 8));
          const ra = Number(this.mem.read(fp + 8, 8));
          fs.push((ra - SO_BASE).toString(16));
          if (prev <= fp) break;
          fp = prev;
        }
        frames = ` frames=${fs.join('<')}`;
      }
      writeFileSync('d:/there/douyinhook/unidbg_work/fmtlog.txt',
        `pc=${pc.toString(16)} lr=${lr.toString(16)}${frames}\t${fmt}\t=>\t${res}\n`, { flag: 'a' });
    }
    return res;
  }

  private runCold(): SoSignResult {
    const c = this.opts.cold!;
    this.loadCold();
    this.coldBuildJni();
    this.installHooks();
    const cpu = this.cpu;
    cpu.svc = (cc, imm) => this.onSvc(cc, imm);

    if (this.verbose) {
      console.log(`[cold] init_array=${this.coldInitArray.length} JNI_OnLoad=0x${this.coldJniOnLoad.toString(16)}`);
    }
    for (let i = 0; i < this.coldInitArray.length; i++) {
      const fn = this.coldInitArray[i];
      if (this.verbose) console.log(`[cold] init_array[${i}] 0x${fn.toString(16)}`);
      this.coldCall(fn, []);
    }
    this.patchInitTime();

    if (this.coldJniOnLoad) {
      const v = this.coldCall(this.coldJniOnLoad, [this.coldVm, 0]);
      if (this.verbose) console.log(`[cold] JNI_OnLoad -> 0x${v.toString(16)}`);
    }
    const exp = this.coldMeta.exports.get('Java_com_bytedance_mobsec_metasec_ml_MS_b');
    // native b 的入口：unidbg 侧即 state_a 快照的 pc（so+0x29b2b4）
    this.coldEntry = this.coldNative.get('b') ?? (exp ? SO_BASE + exp : SO_BASE + 0x29b2b4);
    if (!this.coldEntry) throw new Error('冷启动：找不到 native b（RegisterNatives/导出都没有）');

    const devId = c.deviceId ?? '3933425002887372';
    const insId = c.installId ?? '2486456434296203';
    const str = (s: string): number => this.newHandle({ kind: 'string', val: s });
    const verBytes = new Uint8Array([
      51, 102, 20, 15, 90, 126, 121, 69, 54, 43, 117, 103, 13, 67, 30, 41, 49, 28, 122,
    ]);

    // ---------- i3.java 初始化序列（与 MsSign 完全一致）----------
    this.cpu.histOn = !!process.env.SO_HIST;
    this.coldB(16777219, 0, 0, 0, this.coldApplication);
    this.coldB(33554449, 0, 0, str(''), 0);
    const verH = this.coldB(16777217, 0, 0, str('443549'), this.newHandle({ kind: 'bytearray', val: verBytes }));
    const verObj = this.obj(verH);
    const probedVer = verObj && verObj.kind === 'string' ? String(verObj.val) : 'v04.10.04.01-bugfix';
    if (this.verbose) console.log(`[cold] s4.LIZ -> ${probedVer}`);
    const cfgStr = `["1128","","","${LICENSE}","${probedVer}","","","","","","0","-1","810","","0",[],["tk_key","douyin"]]`;
    this.coldB(67108865, 0, 0, str(cfgStr), 0);
    const hH = this.coldB(67108866, 0, 0, 0, 0);
    const hObj = this.obj(hH);
    const handle2 = hObj && (hObj.kind === 'long' || hObj.kind === 'object')
      ? Number(hObj.val) : 0;
    if (this.verbose) console.log(`[cold] handle2=0x${handle2.toString(16)}`);

    this.coldB(33554434, 0, handle2, str(devId), 0);
    this.coldB(33554435, 0, handle2, str(insId), 0);
    this.coldB(33554446, 0, handle2, str(devId), 0);
    this.coldB(33554448, 1, handle2, str('[]'), 0);
    this.coldB(33554441, 0, handle2, 0, 0);
    this.coldB(33554447, 0, handle2, str(''), this.coldApplication);
    this.coldB(33554433, 0, handle2, str(''), str(''));

    const urlH = str(this.opts.url);
    this.urlHandle = urlH;
    // POST body：byte[] / String 两种形态，与 unidbg 侧 MsSign 的 ByteArray / StringObject 对应
    const bodyH = this.opts.bodyBytes
      ? this.newHandle({ kind: 'bytearray', val: this.opts.bodyBytes })
      : this.opts.body
        ? this.newHandle({ kind: 'string', val: this.opts.body })
        : 0;
    // 预热模式：初始化到 setUrl 之前即停，签名交给 signFast。
    if (this.warmOnly) {
      this.warmOnly = false;
      this.saveBaseline(handle2);
      return {
        headers: {},
        stopReason: 'warm',
        steps: this.steps,
        jniCalls: { ...this.jniCount },
        syscalls: [...new Set(this.svcLog)].sort((a, b) => a - b),
        newStrings: this.nstr,
        retObj: undefined,
      };
    }
    const r1 = this.coldB(33554442, 0, handle2, urlH, 0);
    if (process.env.SO_STEPLOG) console.log(`[cold] setUrl ret=0x${r1.toString(16)} steps=${this.steps}`);
    if (c.dumpDir) this.dumpColdSegs(c.dumpDir);
    if (process.env.SO_STEPLOG) console.log(`[step] before-getFeatureHash steps=${this.steps}`);
    const retH = this.coldB(33554438, 0, handle2, urlH, bodyH);
    if (process.env.SO_STEPLOG) console.log(`[step] after-getFeatureHash steps=${this.steps}`);
    if (process.env.SO_CTXLOG) {
      writeFileSync('d:/there/douyinhook/unidbg_work/ctxtrace_ts.txt', this.ctxTrace.join('\n') + '\n');
    }
    if (process.env.SO_WATCHADDR) {
      writeFileSync('d:/there/douyinhook/unidbg_work/watchaddr.txt', this.ctxTrace.join('\n') + '\n');
    }
    if (c.dumpDir) this.dumpColdSegs(`${c.dumpDir}_after`);
    if (process.env.SO_DUMPAT) {
      for (const spec of process.env.SO_DUMPAT.split(';')) {
        const [as, ls] = spec.split(',');
        const a = Number.parseInt(as, 16);
        const l = Number.parseInt(ls, 16);
        writeFileSync(`d:/there/douyinhook/unidbg_work/dumpat_${a.toString(16)}.bin`,
          Buffer.from(this.mem.slice(a, l)));
      }
    }

    const retObj = this.obj(retH);
    const headers = this.parseHeaders(retH);
    if (process.env.SO_HIST) {
      const h = this.cpu.hist;
      const parts: string[] = [];
      for (let i = 0; i < h.length; i++) if (h[i] !== 0) parts.push(`${i}:${h[i]}`);
      console.log(`[hist] ${parts.join(' ')}`);
    }
    return {
      headers,
      stopReason: `cold: ${Object.keys(headers).length} headers`,
      steps: this.steps,
      jniCalls: { ...this.jniCount },
      syscalls: [...new Set(this.svcLog)].sort((a, b) => a - b),
      newStrings: this.nstr,
      retObj,
    };
  }

  // ------------------------------------------------------ 扩展 so（badger 等）

  /** 冷启动：加载 so → 建 JNIEnv → 装钩子 → 跑 init_array / JNI_OnLoad，只执行一次 */
  coldStart(): void {
    if (this.coldStarted) return;
    if (!this.opts.cold) throw new Error('coldStart 只支持冷启动配置（opts.cold）');
    this.loadCold();
    this.coldBuildJni();
    this.installHooks();
    this.cpu.svc = (cc, imm) => this.onSvc(cc, imm);
    for (const fn of this.coldInitArray) this.coldCall(fn, []);
    if (this.coldJniOnLoad) this.coldCall(this.coldJniOnLoad, [this.coldVm, 0]);
    this.coldStarted = true;
  }

  /** 调用 so 静态注册的 native 函数，返回 x0（参数按真机 JNI 形态排列） */
  coldFn(name: string, args: number[]): number {
    const fn = this.coldNative.get(name);
    if (fn === undefined) throw new Error(`so 未导出 ${name}`);
    this.coldStart();
    return this.coldCall(fn, args);
  }

  /** 按 ELF 导出名调用 so 函数（走 Java_ 静态注册、不用 RegisterNatives 的 so 用这个） */
  coldExport(name: string, args: number[]): number {
    const off = this.coldMeta?.exports.get(name);
    if (off === undefined) throw new Error(`so 未导出 ${name}`);
    this.coldStart();
    return this.coldCall(SO_BASE + off, args);
  }

  /** JNIEnv / class 桩地址：native 的 x0、x1 按真机约定传这两个 */
  get coldEnvAddr(): number {
    return this.coldEnv;
  }

  get coldClassAddr(): number {
    return this.coldClassHandle;
  }

  /** 新建 Java 对象句柄 / 读回句柄内容 */
  makeHandle(obj: Obj): number {
    return this.newHandle(obj);
  }

  readHandle(h: number): Obj | undefined {
    return this.obj(h);
  }

  // ------------------------------------------------------ 预热复用（免重复冷启动）

  /**
   * 预热：只跑一遍初始化序列（init_array/JNI_OnLoad/配置），停在 getFeatureHash 入口前。
   * 之后可反复 signFast：每次只恢复基线内存 + 跑一次 getFeatureHash（约 1/3 指令量，
   * JIT 块已全编译），冷启动的 1.1s 只付一次。
   */
  warmUp(): void {
    if (!this.opts.cold) throw new Error('warmUp 只支持冷启动配置（opts.cold）');
    // 初始化阶段 so 会把「启动时间（毫秒）」写进签名上下文（X-Medusa 会带上它），
    // ts 传 0 会让它变成 1970 年，服务端直接判签名无效（error_code=7）。
    if (!this.ts || this.ts <= 0) this.ts = Math.floor(Date.now() / 1000);
    this.warmOnly = true;
    this.runCold();
  }

  /** 在预热基线上签名（POST 用 body.text / body.bytes，对应 String / byte[]） */
  signFast(url: string, body?: { text?: string; bytes?: Uint8Array }, ts?: number): SoSignResult {
    if (!this.baseline) throw new Error('还没 warmUp()');
    const b = this.baseline;
    this.opts.url = url;
    this.opts.body = body?.text;
    this.opts.bodyBytes = body?.bytes;
    this.ts = ts ?? Math.floor(Date.now() / 1000);
    this.restoreBaseline();
    this.patchInitTime();
    this.objs.set(b.urlHandle, { kind: 'string', val: url });
    const bodyH = body?.bytes
      ? this.newHandle({ kind: 'bytearray', val: body.bytes })
      : body?.text
        ? this.newHandle({ kind: 'string', val: body.text })
        : 0;
    // setUrl 每次都要跑：so 会把 URL 解析成内部结构（不只是读句柄）
    const r1 = this.coldB(33554442, 0, b.handle2, b.urlHandle, 0);
    if (process.env.SO_STEPLOG) console.log(`[fast] setUrl ret=0x${r1.toString(16)} steps=${this.steps}`);
    const s1 = this.steps;
    const retH = this.coldB(33554438, 0, b.handle2, b.urlHandle, bodyH);
    if (process.env.SO_STEPLOG) console.log(`[fast] setUrl=${s1} hash=${this.steps - s1} ret=0x${retH.toString(16)}`);
    const headers = this.parseHeaders(retH);
    return {
      headers,
      stopReason: `warm: ${Object.keys(headers).length} headers`,
      steps: this.steps,
      jniCalls: { ...this.jniCount },
      syscalls: [...new Set(this.svcLog)].sort((a, b2) => a - b2),
      newStrings: this.nstr,
      retObj: this.obj(retH),
    };
  }

  /** 保存 init 完成时的内存页 + 句柄状态（signFast 的恢复原点） */
  private saveBaseline(handle2: number): void {
    const pt = this.mem.pt;
    const pages = new Map<number, Uint8Array>();
    for (let i = 0; i < pt.length; i++) {
      const p = pt[i];
      if (p !== undefined) pages.set(i, p.slice());
    }
    this.baseline = {
      pages,
      objs: new Map(this.objs),
      handle2,
      urlHandle: this.urlHandle,
      nextHandle: this.nextHandle,
      mmapNext: this.mmapNext,
      heap: this.coldHeap,
      monoUs: this.monoUs,
    };
  }

  /** 把内存与句柄状态恢复到基线（新增页丢弃，基线页原地覆写以保住 DataView） */
  private restoreBaseline(): void {
    const b = this.baseline!;
    const pt = this.mem.pt;
    const dv = this.mem.dv;
    for (let i = 0; i < pt.length; i++) {
      const snap = b.pages.get(i);
      if (snap === undefined) {
        if (pt[i] !== undefined) {
          pt[i] = undefined;
          dv[i] = undefined;
        }
        continue;
      }
      let p = pt[i];
      if (p === undefined) {
        p = new Uint8Array(65536);
        pt[i] = p;
        dv[i] = new DataView(p.buffer);
      }
      p.set(snap);
    }
    this.mem.invalidate();
    this.nextHandle = b.nextHandle;
    this.mmapNext = b.mmapNext;
    this.coldHeap = b.heap;
    this.monoUs = b.monoUs;
    this.objs.clear();
    for (const [k, v] of b.objs) this.objs.set(k, v);
    // 每次签名 so 都从头走同一串 dlmalloc 分配，回放游标必须归零
    this.replayIdx = 0;
  }

  /** 返回值（jobject[]）→ 头 map */
  private parseHeaders(retH: number): Record<string, string> {
    const headers: Record<string, string> = {};
    const retObj = this.obj(retH);
    if (retObj && retObj.kind === 'objarray') {
      const items = retObj.val as number[];
      for (let i = 0; i + 1 < items.length; i += 2) {
        const k = this.obj(items[i]);
        const v = this.obj(items[i + 1]);
        if (k && k.kind === 'string') {
          headers[k.val as string] = v && v.kind === 'string' ? (v.val as string) : String(v?.val ?? '');
        }
      }
    }
    return headers;
  }

  /** 调试：按 unidbg 快照的命名把关键区域落盘，便于逐字节 diff */
  private dumpColdSegs(dir: string): void {
    mkdirSync(dir, { recursive: true });
    const pt = this.mem.pt;
    let n = 0;
    for (let i = 0; i < pt.length; i++) {
      const p = pt[i];
      if (p === undefined) continue;
      writeFileSync(join(dir, `p_${i.toString(16).padStart(6, '0')}.bin`), Buffer.from(p));
      n += 1;
    }
    if (this.verbose) console.log(`[cold] dump ${n} pages -> ${dir}`);
  }

  private coldMmap(addr: number, len: number): number {
    const size = (len + 0xfff) & ~0xfff;
    let base: number;
    if (addr !== 0) {
      base = addr & ~0xfff;
    } else {
      base = this.mmapNext;
      this.mmapNext = (base + size + 0xffff) & ~0xffff;
    }
    this.mem.map(base, size);
    this.segs.push([base, size]);
    return base;
  }

  /** 冷启动模式的 syscall：与 oracle 对齐，但 mmap/brk 等必须真实现 */
  private coldSyscall(cpu: Cpu, nr: number): void {
    const x0 = Number(cpu.x[0]);
    const x1 = Number(cpu.x[1]);
    const x2 = Number(cpu.x[2]);
    this.svcLog.push(nr);
    switch (nr) {
      case 174: // getuid
      case 175: // geteuid
        cpu.x[0] = 0n;
        return;
      case 172: // getpid
      case 173: // getppid
      case 178: // gettid
      case 96: // set_tid_address
        cpu.x[0] = BigInt(this.pid);
        return;
      case 56: { // openat
        const path = this.mem.cstr(x1);
        const fd = this.sysOpen(path);
        if (this.verbose) console.log(`[sys] openat(${JSON.stringify(path)}) => ${fd}`);
        cpu.x[0] = BigInt.asUintN(32, BigInt(fd));
        return;
      }
      case 48: // faccessat
      case 34: // mkdirat
      case 79: // newfstatat
        cpu.x[0] = 0xfffffffen;
        return;
      case 80: // fstat
        this.sysFstat(x0 & 0xffffffff, x1);
        cpu.x[0] = 0n;
        return;
      case 63: { // read
        const n = this.sysRead(x0 & 0xffffffff, x1, x2);
        cpu.x[0] = BigInt.asUintN(32, BigInt(n));
        return;
      }
      case 64: // write
        cpu.x[0] = BigInt(x2 & 0xffffffff);
        return;
      case 57: // close
        this.fds.delete(x0 & 0xffffffff);
        cpu.x[0] = 0n;
        return;
      case 113: { // clock_gettime
        const [sec, nsec] = x0 === 0 || x0 === 5 ? [this.ts, FROZEN_SUB] : this.monoTime();
        if (x1) {
          this.mem.write(x1, 8, BigInt(sec));
          this.mem.write(x1 + 8, 8, BigInt(nsec));
        }
        cpu.x[0] = 0n;
        return;
      }
      case 169: // gettimeofday
        if (x0) {
          this.mem.write(x0, 8, BigInt(this.ts));
          this.mem.write(x0 + 8, 8, BigInt(FROZEN_SUB));
        }
        cpu.x[0] = 0n;
        return;
      case 278: { // getrandom
        const n = x1 & 0xffffffff;
        if (x0) this.mem.load(x0, new Uint8Array(n));
        cpu.x[0] = BigInt(n);
        return;
      }
      case 222: { // mmap：与 oracle 一致，直接失败（so 有内部兜底路径）
        if (this.verbose) console.log(`[sys] mmap(0x${x0.toString(16)}, 0x${x1.toString(16)}) => -1`);
        cpu.x[0] = BigInt.asUintN(64, -1n);
        return;
      }
      case 215: // munmap
      case 226: // mprotect
      case 233: // madvise
      case 98: // futex
      case 99: // set_robust_list
      case 167: // prctl
      case 25: // fcntl
      case 29: // ioctl
      case 46: // ftruncate
      case 62: // lseek
      case 124: // sched_yield
      case 123: // sched_getaffinity
      case 131: // rt_sigprocmask
      case 129: // rt_sigqueueinfo
      case 130: // rt_sigsuspend
      case 135: // rt_sigaction
        cpu.x[0] = 0n;
        return;
      case 214: // brk（bionic 的 malloc 走 mmap，这里只需失败）
        cpu.x[0] = BigInt.asUintN(64, -1n);
        return;
      case 220: // clone
        cpu.x[0] = BigInt.asUintN(64, -1n);
        return;
      case 78: // readlinkat
        cpu.x[0] = 0xfffffffen;
        return;
      case 17: { // getcwd
        const p = '/';
        if (x0) this.mem.load(x0, new Uint8Array([0x2f, 0]));
        cpu.x[0] = BigInt(p.length);
        return;
      }
      case 160: // uname
        if (x0) this.mem.load(x0, new Uint8Array(390));
        cpu.x[0] = 0n;
        return;
      case 261: // prlimit64
      case 157: // setsid
        cpu.x[0] = 0n;
        return;
      default:
        if (!this.coldUnknown.has(nr)) {
          this.coldUnknown.add(nr);
          if (this.verbose) {
            console.log(`[sys] cold 未实现 nr=${nr} pc=0x${(cpu.pc - 4).toString(16)} ` +
              `x0=0x${x0.toString(16)} x1=0x${x1.toString(16)} x2=0x${x2.toString(16)} -> 0`);
          }
        }
        cpu.x[0] = 0n;
        return;
    }
  }
}
