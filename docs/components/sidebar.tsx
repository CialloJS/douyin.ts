'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { ScrollShadow } from '@heroui/react'
import { sections } from '@/lib/nav'

/** 路径尾部斜杠先去掉，避免 /docs/guide/ 与 /docs/guide 判定不一致 */
function useActive (): (slug: string) => boolean {
  const pathname = usePathname()
  const path = pathname.replace(/\/+$/, '')
  return (slug: string): boolean => path.endsWith(`/docs/${slug}`)
}

const item = 'flex rounded-lg px-2.5 py-1.5 text-[13.5px] leading-5 transition-colors outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-brand)]/40'

/** 桌面侧边栏与移动抽屉共用同一份导航结构，避免两套手写列表产生偏差 */
export function NavTree ({ desc = false, onPick }: { desc?: boolean; onPick?: () => void }) {
  const active = useActive()

  return (
    <nav aria-label="文档导航">
      {sections.map((section, index) => (
        <div key={section.title} className={index ? 'mt-7' : ''}>
          <p className="mb-2 px-2.5 text-[11px] font-semibold tracking-[0.14em] text-neutral-400 uppercase">
            {section.title}
          </p>
          <ul className="space-y-0.5">
            {section.docs.map(doc => {
              const on = active(doc.slug)
              return (
                <li key={doc.slug}>
                  <Link
                    href={`/docs/${doc.slug}`}
                    onClick={onPick}
                    aria-current={on ? 'page' : undefined}
                    className={`${item} ${desc ? 'items-start gap-2.5 py-2.5' : ''} ${
                      on
                        ? 'bg-[color-mix(in_oklab,var(--color-brand)_10%,transparent)] font-medium text-[var(--color-brand)]'
                        : 'text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-900 dark:hover:text-neutral-100'
                    }`}
                  >
                    {desc && (
                      <span className={`mt-2 h-1.5 w-1.5 shrink-0 rounded-full ${on ? 'bg-[var(--color-brand)]' : 'bg-neutral-300 dark:bg-neutral-700'}`} />
                    )}
                    {desc
                      ? (
                        <span className="min-w-0">
                          <span className="block text-sm leading-5 font-medium">{doc.title}</span>
                          <span className={`mt-0.5 block truncate text-xs ${on ? 'opacity-70' : 'text-neutral-500'}`}>
                            {doc.summary}
                          </span>
                        </span>
                        )
                      : doc.title}
                  </Link>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )
}

export function Sidebar () {
  return (
    <aside className="hidden w-52 shrink-0 md:block lg:w-60">
      <ScrollShadow
        hideScrollBar
        size={28}
        className="sticky top-16 max-h-[calc(100dvh-5rem)] overflow-y-auto py-8 pr-2"
      >
        <NavTree />
      </ScrollShadow>
    </aside>
  )
}
