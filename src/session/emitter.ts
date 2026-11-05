/**
 * 类型化事件分发：把 on/emit 之间的类型断言收敛在本文件，业务侧保持推导。
 */
type Handler = (...args: unknown[]) => void

export class Emitter<M extends Record<string, unknown[]>> {
  private readonly map = new Map<keyof M, Set<Handler>>()

  on<K extends keyof M> (event: K, fn: (...args: M[K]) => void): void {
    const set = this.map.get(event) ?? new Set<Handler>()
    // 断言只在此处：fn 的参数已由调用侧 M[K] 约束，存储时与具体事件解耦
    set.add(fn as Handler)
    this.map.set(event, set)
  }

  off<K extends keyof M> (event: K, fn: (...args: M[K]) => void): void {
    this.map.get(event)?.delete(fn as Handler)
  }

  protected emit<K extends keyof M> (event: K, ...args: M[K]): void {
    for (const fn of this.map.get(event) ?? []) fn(...args)
  }
}
