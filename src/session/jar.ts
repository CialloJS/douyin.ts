/** 精简 Cookie 会话：抖音全站共享一份键值对，不区分 domain/path */
const ATTRIBUTES = new Set(['path', 'domain', 'expires', 'max-age', 'secure', 'httponly', 'samesite'])

export class Jar {
  private readonly store = new Map<string, string>()

  constructor (initial?: string) {
    if (initial) this.merge(initial)
  }

  get (name: string): string | undefined {
    return this.store.get(name)
  }

  has (name: string): boolean {
    return this.store.has(name)
  }

  set (name: string, value: string): void {
    this.store.set(name, value)
  }

  delete (name: string): void {
    this.store.delete(name)
  }

  /** 导入 Cookie 请求头；响应 Set-Cookie 走 absorb 以支持过期删除 */
  merge (raw: string): void {
    for (const part of raw.split(/[;\n]/)) {
      const eq = part.indexOf('=')
      if (eq <= 0) continue
      const name = part.slice(0, eq).trim()
      if (name && !ATTRIBUTES.has(name.toLowerCase())) this.store.set(name, part.slice(eq + 1).trim())
    }
  }

  header (): string {
    return [...this.store].map(([key, value]) => `${key}=${value}`).join('; ')
  }

  /** 接受独立或合并的 Set-Cookie（容忍 Expires 中的逗号）；max-age<=0 或已过期则删除 */
  absorb (raw: string, now = Date.now()): void {
    for (const line of raw.split(/,(?=\s*[^\s;,=]+\s*=)/)) {
      const [pair, ...attrs] = line.split(';')
      const eq = pair?.indexOf('=') ?? -1
      if (!pair || eq <= 0) continue
      const name = pair.slice(0, eq).trim()
      const value = pair.slice(eq + 1).trim()
      let maxAge: number | undefined
      let expires: number | undefined
      for (const attr of attrs) {
        const sep = attr.indexOf('=')
        if (sep < 0) continue
        const key = attr.slice(0, sep).trim().toLowerCase()
        const val = attr.slice(sep + 1).trim()
        if (key === 'max-age' && /^-?\d+$/.test(val)) maxAge = Number(val)
        if (key === 'expires') expires = Date.parse(val)
      }
      const deleted = maxAge !== undefined ? maxAge <= 0 : expires !== undefined && expires <= now
      if (deleted) this.store.delete(name)
      else this.store.set(name, value)
    }
  }
}
