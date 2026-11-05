import Link from 'next/link'
import { buttonVariants } from '@heroui/react'
import { Logo } from '@/components/logo'
import { SiteHeader } from '@/components/site-header'

export default function NotFound () {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto flex max-w-[720px] flex-col items-center px-4 py-28 text-center">
        <Logo size={44} />
        <p className="mt-6 text-[11px] font-semibold uppercase tracking-[0.3em] text-neutral-400">404</p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">页面走丢了</h1>
        <p className="mt-2 text-sm text-neutral-500">链接可能已调整，回到文档首页重新找找。</p>
        <div className="mt-8 flex gap-3">
          <Link href="/docs/guide" className={buttonVariants({ variant: 'primary' })}>快速开始</Link>
          <Link href="/" className={buttonVariants({ variant: 'outline' })}>返回首页</Link>
        </div>
      </main>
    </>
  )
}
