'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useMemo, useState } from 'react'
import { Menu, Search } from 'lucide-react'
import { Button, Chip, Drawer, SearchField } from '@heroui/react'
import { allDocs } from '@/lib/nav'
import { Logo } from './logo'
import { NavTree } from './sidebar'
import { ThemeToggle } from './theme-toggle'

const primary = [
  { href: '/docs/guide', label: '指南' },
  { href: '/docs/events/message', label: '事件' },
  { href: '/docs/api/msg', label: 'API' },
]

/** 路径尾部斜杠先去掉，避免 /docs/guide/ 与 /docs/guide 判定不一致 */
function useMatch (): (href: string) => boolean {
  const pathname = usePathname()
  const path = pathname.replace(/\/+$/, '')
  return (href: string): boolean => path.endsWith(href)
}

export function MobileNav () {
  const [mode, setMode] = useState<'nav' | 'search' | null>(null)

  return (
    <>
      <div className="flex items-center gap-0.5 md:hidden">
        <Button isIconOnly size="sm" variant="ghost" aria-label="搜索文档" className="h-10 w-10" onPress={() => setMode('search')}>
          <Search size={18} strokeWidth={1.8} />
        </Button>
        <ThemeToggle />
        <Button isIconOnly size="sm" variant="ghost" aria-label="打开导航" className="h-10 w-10" onPress={() => setMode('nav')}>
          <Menu size={19} strokeWidth={1.8} />
        </Button>
      </div>
      <NavDrawer open={mode === 'nav'} onOpenChange={open => setMode(open ? 'nav' : null)} />
      <SearchDrawer open={mode === 'search'} onOpenChange={open => setMode(open ? 'search' : null)} />
    </>
  )
}

function NavDrawer ({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const isActive = useMatch()

  return (
    <Drawer.Root isOpen={open} onOpenChange={onOpenChange}>
      <Drawer.Backdrop className="md:hidden" variant="blur">
        <Drawer.Content placement="left">
          <Drawer.Dialog aria-label="文档导航" className="bg-white p-0 dark:bg-[#0d0d10]">
            <Drawer.Header className="flex-row items-center gap-2 border-b border-neutral-200 px-4 py-3 pt-[calc(0.75rem+env(safe-area-inset-top))] dark:border-neutral-800">
              <Link href="/" className="flex min-w-0 items-center gap-2">
                <Logo size={22} />
                <span className="text-[15px] font-semibold tracking-tight">douyin.ts</span>
                <Chip size="sm" variant="soft" color="accent">v0.6</Chip>
              </Link>
              <Drawer.CloseTrigger className="static ml-auto" aria-label="关闭导航" />
            </Drawer.Header>

            <Drawer.Body className="px-3 py-3">
              <div className="mb-5 grid grid-cols-3 gap-2">
                {primary.map(link => {
                  const active = isActive(link.href)
                  return (
                    <Link
                      key={link.href}
                      href={link.href}
                      className={`flex h-11 items-center justify-center rounded-xl border text-[13px] transition-colors ${
                        active
                          ? 'border-neutral-900 bg-neutral-900 font-medium text-white dark:border-white dark:bg-white dark:text-neutral-900'
                          : 'border-neutral-200 text-neutral-600 active:bg-neutral-100 dark:border-neutral-800 dark:text-neutral-400 dark:active:bg-neutral-900'
                      }`}
                    >
                      {link.label}
                    </Link>
                  )
                })}
              </div>

              <NavTree desc onPick={() => onOpenChange(false)} />
            </Drawer.Body>

            <Drawer.Footer className="justify-between border-t border-neutral-200 px-4 py-3 pb-[calc(0.75rem+env(safe-area-inset-bottom))] dark:border-neutral-800">
              <span className="text-[11px] text-neutral-400">Node ≥ 20 · 纯 ESM</span>
              <a
                href="https://github.com/CialloJS/douyin.ts"
                target="_blank"
                rel="noreferrer"
                className="text-[12px] text-neutral-500 transition-colors active:text-neutral-900 dark:text-neutral-400 dark:active:text-white"
              >
                GitHub
              </a>
            </Drawer.Footer>
          </Drawer.Dialog>
        </Drawer.Content>
      </Drawer.Backdrop>
    </Drawer.Root>
  )
}

function SearchDrawer ({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [q, setQ] = useState('')

  const results = useMemo(() => {
    const key = q.trim().toLowerCase()
    if (!key) return allDocs()
    return allDocs().filter(doc => `${doc.title} ${doc.summary} ${doc.slug}`.toLowerCase().includes(key))
  }, [q])

  const change = (next: boolean): void => {
    if (!next) setQ('')
    onOpenChange(next)
  }

  return (
    <Drawer.Root isOpen={open} onOpenChange={change}>
      <Drawer.Backdrop className="md:hidden" variant="blur">
        <Drawer.Content placement="top">
          <Drawer.Dialog aria-label="搜索文档" className="max-h-[85dvh] rounded-b-2xl bg-white p-0 dark:bg-[#0d0d10]">
            <div className="border-b border-neutral-200 px-3 py-2.5 pt-[calc(0.625rem+env(safe-area-inset-top))] dark:border-neutral-800">
              <SearchField fullWidth autoFocus aria-label="搜索文档" value={q} onChange={setQ}>
                <SearchField.Group>
                  <SearchField.SearchIcon />
                  <SearchField.Input placeholder="搜索文档、事件、API" />
                  <SearchField.ClearButton />
                </SearchField.Group>
              </SearchField>
            </div>
            <Drawer.Body className="p-0">
              {results.length === 0
                ? <p className="px-4 py-6 text-center text-[13px] text-neutral-500">没有匹配的文档</p>
                : (
                  <>
                    {!q.trim() && <p className="px-4 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-widest text-neutral-400">全部文档</p>}
                    {results.map(doc => (
                      <Link
                        key={doc.slug}
                        href={`/docs/${doc.slug}`}
                        onClick={() => change(false)}
                        className="flex flex-col gap-0.5 px-4 py-2.5 transition-colors active:bg-neutral-100 dark:active:bg-neutral-900"
                      >
                        <span className="text-[14px] font-medium">{doc.title}</span>
                        <span className="truncate text-[12px] text-neutral-500">{doc.summary}</span>
                      </Link>
                    ))}
                  </>
                )}
            </Drawer.Body>
          </Drawer.Dialog>
        </Drawer.Content>
      </Drawer.Backdrop>
    </Drawer.Root>
  )
}

