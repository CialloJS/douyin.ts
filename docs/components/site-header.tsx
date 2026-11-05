'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Chip } from '@heroui/react'
import { Logo } from './logo'
import { MobileNav } from './mobile-nav'
import { Search } from './search'
import { ThemeToggle } from './theme-toggle'

const links = [
  { href: '/docs/guide', label: '指南' },
  { href: '/docs/events/message', label: '事件' },
  { href: '/docs/api/msg', label: 'API' },
]

export function SiteHeader () {
  const pathname = usePathname()
  return (
    <header className="sticky top-0 z-40 border-b border-neutral-200/80 bg-white/85 backdrop-blur pt-[env(safe-area-inset-top)] dark:border-neutral-800/80 dark:bg-[#0a0a0c]/85">
      <div className="mx-auto flex h-14 max-w-[1320px] items-center gap-3 px-4 md:h-16">
        <Link href="/" className="flex min-w-0 items-center gap-2.5">
          <Logo size={26} />
          <span className="text-[15px] font-semibold tracking-tight">douyin.ts</span>
          <Chip size="sm" variant="soft" color="accent" className="hidden sm:inline-flex">v0.6</Chip>
        </Link>
        <nav className="ml-2 hidden items-center gap-1 md:flex">
          {links.map(link => {
            const active = pathname.includes(link.href)
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={active ? 'page' : undefined}
                className={`rounded-lg px-3 py-1.5 text-sm transition-colors ${
                  active
                    ? 'bg-neutral-100 font-medium text-neutral-900 dark:bg-neutral-800 dark:text-white'
                    : 'text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white'
                }`}
              >
                {link.label}
              </Link>
            )
          })}
        </nav>
        <div className="ml-auto flex items-center gap-1.5">
          <div className="hidden items-center gap-1.5 md:flex">
            <Search />
            <ThemeToggle />
            <a
              href="https://github.com/CialloJS/douyin.ts"
              target="_blank"
              rel="noreferrer"
              aria-label="GitHub"
              className="flex h-9 w-9 items-center justify-center rounded-lg text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-white"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M12 2a10 10 0 0 0-3.2 19.5c.5.1.7-.2.7-.5v-1.7c-2.8.6-3.4-1.3-3.4-1.3-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.5 2.3 1.1 2.9.8.1-.7.4-1.1.6-1.4-2.2-.3-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.7 1a9.4 9.4 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.4.2 2.4.1 2.7.6.7 1 1.6 1 2.7 0 3.9-2.4 4.7-4.6 5 .4.3.7.9.7 1.9v2.8c0 .3.2.6.7.5A10 10 0 0 0 12 2z" />
              </svg>
            </a>
          </div>
          <MobileNav />
        </div>
      </div>
    </header>
  )
}
