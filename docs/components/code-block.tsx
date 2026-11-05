'use client'

import type { ComponentProps } from 'react'
import { useRef, useState } from 'react'

/** 代码块：保留 MDX 传入的 pre 结构，附加复制按钮 */
export function CodeBlock ({ className, ...props }: ComponentProps<'pre'>) {
  const ref = useRef<HTMLPreElement>(null)
  const [copied, setCopied] = useState(false)
  const language = className?.match(/language-(\w+)/)?.[1]

  const copy = async (): Promise<void> => {
    const text = ref.current?.innerText ?? ''
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1600)
  }

  return (
    <div className="group relative my-5 overflow-hidden rounded-xl border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-[#101014]">
      {language && (
        <span className="absolute left-3 top-2.5 text-[11px] font-medium uppercase tracking-wider text-neutral-400 sm:left-4 sm:top-3">
          {language}
        </span>
      )}
      <button
        type="button"
        onClick={copy}
        className="absolute right-2.5 top-2 rounded-md border border-neutral-200 bg-white px-2 py-1 text-[11px] text-neutral-500 transition-opacity hover:text-neutral-900 md:opacity-0 md:group-hover:opacity-100 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-400 dark:hover:text-white"
      >
        {copied ? '已复制' : '复制'}
      </button>
      <pre
        ref={ref}
        {...props}
        className={`code-scroll overflow-x-auto px-3 pb-4 text-[12.5px] leading-[1.7] sm:px-4 sm:text-[13px] sm:leading-6 ${language ? 'pt-8 sm:pt-9' : 'pt-4'} ${className ?? ''}`}
      />
    </div>
  )
}
