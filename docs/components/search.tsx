'use client'

import Link from 'next/link'
import { useMemo, useState } from 'react'
import { SearchField } from '@heroui/react'
import { allDocs } from '@/lib/nav'

/** 纯前端过滤：文档规模小，无需索引服务 */
export function Search () {
  const [q, setQ] = useState('')
  const results = useMemo(() => {
    const key = q.trim().toLowerCase()
    if (!key) return []
    return allDocs()
      .filter(doc => `${doc.title} ${doc.summary} ${doc.slug}`.toLowerCase().includes(key))
      .slice(0, 8)
  }, [q])

  return (
    <div className="relative hidden md:block">
      <SearchField
        aria-label="搜索文档"
        value={q}
        onChange={setQ}
        className="w-44 transition-[width] focus-within:w-56"
      >
        <SearchField.Group className="w-full">
          <SearchField.SearchIcon />
          <SearchField.Input placeholder="搜索文档" />
        </SearchField.Group>
      </SearchField>
      {q.trim() && (
        <div className="absolute top-11 right-0 z-50 w-80 overflow-hidden rounded-xl border border-neutral-200 bg-white shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
          {results.length === 0
            ? <p className="px-4 py-3 text-sm text-neutral-500">没有匹配的文档</p>
            : results.map(doc => (
              <Link
                key={doc.slug}
                href={`/docs/${doc.slug}`}
                onClick={() => setQ('')}
                className="flex flex-col gap-0.5 px-4 py-2.5 transition-colors hover:bg-neutral-50 dark:hover:bg-neutral-800"
              >
                <span className="text-sm font-medium">{doc.title}</span>
                <span className="text-xs text-neutral-500">{doc.summary}</span>
              </Link>
            ))}
        </div>
      )}
    </div>
  )
}
