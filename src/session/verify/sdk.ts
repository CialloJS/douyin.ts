/** 本地静态资源:React 运行时与官方 SecondVerify SDK */
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { assetDir } from '../../asset.js'

/** 资源随包发布,运行期只读盘一次 */
function asset (file: string): Promise<Buffer> {
  return readFile(join(assetDir(file), file))
}

export function loadReact (): Promise<[Buffer, Buffer]> {
  return Promise.all([
    asset('react.production.min.js'),
    asset('react-dom.production.min.js'),
  ])
}

/** 决策未带 url 时用本地内置官方 SDK;缓存避免每轮验证重复读盘 */
let cached: Promise<Buffer> | undefined
export function loadSdk (): Promise<Buffer> {
  cached ??= asset('second-verification-web.js')
  return cached
}
