/** 昵称缓存：事件下发要带发送者昵称，列表接口结果顺带入缓存；TTL 内直接用，过期整体刷新 */
import type { NickEntry } from './address.js'

const now = (): number => Date.now()

export class Nicks {
  private static readonly TTL = 60_000
  private readonly map = new Map<string, string>()
  private readonly at = new Map<string, number>()
  private readonly pending = new Map<string, Promise<void>>()

  set (uid: string, nickname: string): void {
    this.map.set(uid, nickname)
    this.at.set(uid, now())
  }

  has (uid: string): boolean {
    return this.map.has(uid)
  }

  /** TTL 过期视为未命中：昵称会变更，避免长期陈旧 */
  get (uid: string): string | undefined {
    if (!this.map.has(uid)) return undefined
    return now() - (this.at.get(uid) ?? 0) < Nicks.TTL ? this.map.get(uid) : undefined
  }

  remember (entries: readonly NickEntry[]): void {
    for (const entry of entries) {
      const nickname = entry.alias ?? entry.nickname
      if (nickname) this.set(entry.uid, nickname)
    }
  }

  /** 同一 uid 并发补拉只发一次请求，失败静默由下一条消息重试 */
  async once (uid: string, load: () => Promise<void>): Promise<void> {
    const pending = this.pending.get(uid)
    if (pending) return pending
    const task = load()
      .catch(() => undefined)
      .finally(() => { this.pending.delete(uid) })
    this.pending.set(uid, task)
    return task
  }
}
