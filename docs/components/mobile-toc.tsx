'use client'

import { useEffect, useState } from 'react'
import { Drawer } from '@heroui/react'
import type { Heading } from './toc'

/** 目录条目在视口顶部 88px 内最先出现的高亮 */
function useActive (headings: Heading[], open: boolean): string {
  const [id, setId] = useState('')

  useEffect(() => {
    if (!open || headings.length === 0) return
    const targets = headings
      .map(heading => document.getElementById(heading.id))
      .filter((el): el is HTMLElement => el !== null)
    const observer = new IntersectionObserver(records => {
      const visible = records
        .filter(record => record.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)
      if (visible[0]) setId(visible[0].target.id)
    }, { rootMargin: '-88px 0px -65% 0px' })
    targets.forEach(target => observer.observe(target))
    return () => observer.disconnect()
  }, [headings, open])

  return id
}

/** 文档页小屏：吸顶面包屑 + 官方 Drawer 底部目录 */
export function MobileToc ({ title, section, headings }: { title: string; section?: string; headings: Heading[] }) {
  const [open, setOpen] = useState(false)
  const active = useActive(headings, open)
  const usable = headings.length > 0

  return (
    <>
      <div className="sticky top-[calc(3.5rem+env(safe-area-inset-top))] z-20 -mx-4 mb-6 flex items-center gap-3 border-b border-neutral-200 bg-white/90 px-4 py-2 backdrop-blur md:hidden dark:border-neutral-800 dark:bg-[#0a0a0c]/90">
        <p className="min-w-0 flex-1 truncate text-[12.5px] leading-5">
          {section && <span className="text-neutral-400">{section} / </span>}
          <span className="font-medium text-neutral-900 dark:text-neutral-200">{title}</span>
        </p>
        {usable && (
          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-label="打开本页目录"
            className="flex shrink-0 items-center gap-1.5 rounded-lg border border-neutral-200 px-2.5 py-1.5 text-[12px] text-neutral-600 transition-colors active:bg-neutral-100 dark:border-neutral-800 dark:text-neutral-400 dark:active:bg-neutral-900"
          >
            <ListIcon />
            目录
          </button>
        )}
      </div>

      {usable && (
        <Drawer.Root isOpen={open} onOpenChange={setOpen}>
          <Drawer.Backdrop className="md:hidden" variant="blur">
            <Drawer.Content placement="bottom">
              <Drawer.Dialog aria-label="本页目录" className="max-h-[72dvh] bg-white p-0 dark:bg-[#0d0d10]">
                <Drawer.Handle />
                <Drawer.Header className="flex-row items-center justify-between px-4 pb-2">
                  <Drawer.Heading className="text-[13px] font-semibold">本页目录</Drawer.Heading>
                  <Drawer.CloseTrigger className="static" aria-label="关闭目录" />
                </Drawer.Header>
                <Drawer.Body className="px-2 pb-[calc(1rem+env(safe-area-inset-bottom))]">
                  <ul>
                    {headings.map(heading => {
                      const on = heading.id === active
                      return (
                        <li key={heading.id}>
                          <a
                            href={`#${heading.id}`}
                            onClick={() => setOpen(false)}
                            className={`flex items-start gap-2 rounded-lg px-3 py-2.5 text-[13.5px] leading-5 transition-colors ${
                              on
                                ? 'bg-neutral-100 font-medium text-neutral-900 dark:bg-neutral-900 dark:text-white'
                                : 'text-neutral-600 active:bg-neutral-50 dark:text-neutral-400 dark:active:bg-neutral-900'
                            }`}
                          >
                            <span className={`mt-[5px] h-1 w-1 shrink-0 rounded-full ${on ? 'bg-[var(--color-brand)]' : 'bg-neutral-300 dark:bg-neutral-700'}`} />
                            {heading.text}
                          </a>
                        </li>
                      )
                    })}
                  </ul>
                </Drawer.Body>
              </Drawer.Dialog>
            </Drawer.Content>
          </Drawer.Backdrop>
        </Drawer.Root>
      )}
    </>
  )
}

function ListIcon () {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9">
      <path d="M5 7h14M5 12h14M5 17h9" strokeLinecap="round" />
    </svg>
  )
}
