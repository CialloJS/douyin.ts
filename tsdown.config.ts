import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: 'esm',
  platform: 'node',
  dts: true,
  // 可选依赖：装了才启用自动过滑块，不装回落扫码，不能打进产物
  deps: { neverBundle: ['playwright-core'] },
})
