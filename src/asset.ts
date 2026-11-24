/** 内置静态资源定位：源码在 src/、打包在 dist/，两种布局都从包根 assets 取 */
import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

/** 资源所在目录；找不到返回空串，供「可选资源」自行降级 */
export function findAsset (name: string): string {
  return [resolve(here, '../assets'), resolve(process.cwd(), 'assets')]
    .find(dir => existsSync(join(dir, name))) ?? ''
}

/** 资源所在目录；缺失即抛错，避免 readFile 抛模糊的 ENOENT */
export function assetDir (name: string): string {
  const dir = findAsset(name)
  if (!dir) throw new Error(`找不到 assets/${name}`)
  return dir
}
