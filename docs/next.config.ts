import createMDX from '@next/mdx'
import type { NextConfig } from 'next'

// GitHub Pages 项目站点部署在 /douyin.ts/ 下；本地开发留空
const base = process.env.DOCS_BASE ?? ''

const config: NextConfig = {
  output: 'export',
  basePath: base,
  assetPrefix: base || undefined,
  trailingSlash: true,
  images: { unoptimized: true },
  pageExtensions: ['ts', 'tsx', 'mdx'],
  typedRoutes: false,
}

// Turbopack 的 loader options 必须可序列化，插件用包名字符串而非函数引用
export default createMDX({ options: { remarkPlugins: ['remark-gfm'] } })(config)
