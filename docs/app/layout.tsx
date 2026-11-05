import type { Metadata, Viewport } from 'next'
import { NOTE_PATH } from '@/components/logo'
import './globals.css'

// 图标只保留音符轮廓，不加彩色底板
const iconSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#111" d="${NOTE_PATH}"/></svg>`

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#ffffff' },
    { media: '(prefers-color-scheme: dark)', color: '#0a0a0c' },
  ],
}

export const metadata: Metadata = {
  title: { default: 'douyin.ts · 抖音 IM 机器人 SDK', template: '%s · douyin.ts' },
  description: '抖音 IM 机器人 SDK：TypeScript 7、纯 ESM、Node ≥ 20。扫码登录、消息收发、富媒体与群管理。',
  icons: {
    icon: `data:image/svg+xml,${encodeURIComponent(iconSvg)}`,
  },
}

// 首屏前置切换暗色，避免刷新闪烁
const themeScript = `(() => {
  try {
    const saved = localStorage.getItem('theme')
    const dark = saved ? saved === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches
    if (dark) document.documentElement.classList.add('dark')
  } catch {}
})()`

export default function RootLayout ({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN" data-scroll-behavior="smooth" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="min-h-screen bg-white text-neutral-900 antialiased dark:bg-[#0a0a0c] dark:text-neutral-100">
        {children}
      </body>
    </html>
  )
}
