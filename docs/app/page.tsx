import type { Metadata } from 'next'
import Link from 'next/link'
import { buttonVariants, Card, CardContent, CardDescription, CardHeader, CardTitle, Chip } from '@heroui/react'
import { SiteHeader } from '@/components/site-header'
import { sections } from '@/lib/nav'

export const metadata: Metadata = {
  title: 'douyin.ts · 抖音 IM 机器人 SDK',
}

const features = [
  {
    title: '扫码即用',
    desc: '二维码、滑块、短信、密码与上行短信，二次验证全流程回调交付，不接管交互。',
  },
  {
    title: 'WS + HTTP 双通道',
    desc: 'Android Frontier 长连收消息，桌面 HTTP 通道发消息，断线自动重连。',
  },
  {
    title: '富媒体',
    desc: '图片、视频、文件上传，CENC 加密视频解密，表情与合并转发开箱即用。',
  },
  {
    title: '类型化错误',
    desc: 'SdkError.data 原样携带上游响应或失败字段，调用方不解析文案即可分支。',
  },
  {
    title: '能力分层',
    desc: 'bot.域.动作 两级门面，msg / media / chat / contact / notice 按需调用。',
  },
  {
    title: '纯 ESM',
    desc: 'TypeScript 7 严格模式，Node ≥ 20，无 CJS 兼容层与运行时依赖注入。',
  },
]

export default function HomePage () {
  return (
    <>
      <SiteHeader />
      <main>
        <section className="relative overflow-hidden border-b border-neutral-200 dark:border-neutral-800">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_60%_at_50%_0%,rgba(254,44,85,0.12),transparent)] dark:bg-[radial-gradient(60%_60%_at_50%_0%,rgba(254,44,85,0.18),transparent)]" />
          <div className="relative mx-auto max-w-[1120px] px-4 py-12 sm:py-16 lg:py-24">
            <div className="max-w-2xl">
              <Chip size="sm" variant="soft" color="accent">Node ≥ 20 · TypeScript 7 · 纯 ESM</Chip>
              <h1 className="mt-5 text-[32px] font-semibold leading-[1.15] tracking-tight sm:text-4xl lg:text-5xl">
                抖音 IM 机器人
                <br />
                <span className="bg-gradient-to-r from-[#fe2c55] via-[#ff5f7a] to-[#7b2cff] bg-clip-text text-transparent">
                  用 TypeScript 写
                </span>
              </h1>
              <p className="mt-5 max-w-xl text-[15px] leading-7 text-neutral-600 dark:text-neutral-400">
                一个类型完整、错误可判的抖音私信 SDK。登录、收消息、发消息、富媒体、好友与群管理，
                统一收在 <span className="font-mono text-[13px] text-neutral-900 dark:text-white">bot.域.动作</span> 两层门面里。
              </p>
              <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                <Link href="/docs/guide" className={buttonVariants({ variant: 'primary', size: 'lg' })}>快速开始</Link>
                <Link href="/docs/api/msg" className={buttonVariants({ variant: 'outline', size: 'lg' })}>API 参考</Link>
              </div>
              <InstallCommand />
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-[1120px] px-4 py-16">
          <div className="mb-8 flex items-end justify-between gap-4">
            <div>
              <h2 className="text-2xl font-semibold tracking-tight">为什么用它</h2>
              <p className="mt-1.5 text-sm text-neutral-500">行为约定比功能数量更重要。</p>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {features.map(item => (
              <Card key={item.title} className="border border-neutral-200 bg-white transition-colors hover:border-neutral-400 dark:border-neutral-800 dark:bg-neutral-900/40 dark:hover:border-neutral-600">
                <CardHeader>
                  <CardTitle className="text-[15px] font-semibold">{item.title}</CardTitle>
                </CardHeader>
                <CardContent className="pb-5">
                  <CardDescription className="text-[13.5px] leading-6">{item.desc}</CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        <section className="border-t border-neutral-200 bg-neutral-50/60 dark:border-neutral-800 dark:bg-neutral-900/30">
          <div className="mx-auto max-w-[1120px] px-4 py-16">
            <h2 className="text-2xl font-semibold tracking-tight">文档</h2>
            <p className="mt-1.5 text-sm text-neutral-500">按能力域组织，先读指南再查 API。</p>
            <div className="mt-8 grid gap-5 md:grid-cols-3">
              {sections.map(section => (
                <div key={section.title}>
                  <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-neutral-400">{section.title}</p>
                  <div className="space-y-1.5">
                    {section.docs.map(doc => (
                      <Link
                        key={doc.slug}
                        href={`/docs/${doc.slug}`}
                        className="block rounded-lg border border-transparent px-3 py-2 transition-colors hover:border-neutral-200 hover:bg-white dark:hover:border-neutral-800 dark:hover:bg-neutral-900"
                      >
                        <p className="text-sm font-medium">{doc.title}</p>
                        <p className="text-xs text-neutral-500">{doc.summary}</p>
                      </Link>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>
      <footer className="border-t border-neutral-200 py-10 dark:border-neutral-800">
        <div className="mx-auto flex max-w-[1120px] flex-col gap-2 px-4 text-xs text-neutral-500 sm:flex-row sm:items-center sm:justify-between">
          <p>基于 MIT 许可发布 · Copyright © 2026 CialloJS</p>
          <p>参考 zhinjs/douyin-im 的实现思路</p>
        </div>
      </footer>
    </>
  )
}

function InstallCommand () {
  return (
    <div className="mt-7 inline-flex items-center gap-2 rounded-xl border border-neutral-200 bg-neutral-50 px-3 py-2 font-mono text-[12.5px] text-neutral-700 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300">
      <span className="text-neutral-400">$</span>
      pnpm add douyin.ts
    </div>
  )
}
