import type { MDXComponents } from 'mdx/types'
import Link from 'next/link'
import { CodeBlock } from './components/code-block'
import { slugify } from './lib/slug'

function textOf (node: unknown): string {
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(textOf).join('')
  if (node && typeof node === 'object' && 'props' in node) {
    return textOf((node as { props: { children?: unknown } }).props.children)
  }
  return ''
}

const anchor = 'text-[var(--color-brand)] underline decoration-[var(--color-brand)]/30 underline-offset-4 transition-colors hover:decoration-[var(--color-brand)]'

export function useMDXComponents (components: MDXComponents): MDXComponents {
  return {
    ...components,
    h1: ({ children }) => <h1 className="mb-3 text-[24px] font-semibold tracking-tight sm:text-[28px]">{children}</h1>,
    h2: ({ children }) => (
      <h2 id={slugify(textOf(children))} className="mt-9 mb-3 scroll-mt-28 border-b border-neutral-200 pb-2 text-[19px] font-semibold tracking-tight sm:mt-10 sm:text-xl dark:border-neutral-800">
        {children}
      </h2>
    ),
    h3: ({ children }) => <h3 className="mt-7 mb-2 scroll-mt-28 text-base font-semibold">{children}</h3>,
    h4: ({ children }) => <h4 className="mt-5 mb-1.5 text-sm font-semibold">{children}</h4>,
    p: ({ children }) => <p className="my-3 leading-7 text-[14.5px] text-neutral-700 dark:text-neutral-300">{children}</p>,
    ul: ({ children }) => <ul className="my-3 list-disc space-y-1.5 pl-5 text-[14.5px] leading-7 text-neutral-700 dark:text-neutral-300">{children}</ul>,
    ol: ({ children }) => <ol className="my-3 list-decimal space-y-1.5 pl-5 text-[14.5px] leading-7 text-neutral-700 dark:text-neutral-300">{children}</ol>,
    li: ({ children }) => <li className="marker:text-neutral-400">{children}</li>,
    strong: ({ children }) => <strong className="font-semibold text-neutral-900 dark:text-white">{children}</strong>,
    blockquote: ({ children }) => (
      <div className="my-4 rounded-r-lg border-l-2 border-[var(--color-brand)] bg-neutral-50 py-0.5 pl-4 dark:bg-neutral-900">
        {children}
      </div>
    ),
    code: ({ children, className }) => (
      <code className={`rounded bg-neutral-100 px-1.5 py-0.5 font-mono text-[13px] text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200 ${className ?? ''}`}>
        {children}
      </code>
    ),
    pre: CodeBlock,
    a: ({ href = '', children }) => href.startsWith('http')
      ? <a href={href} target="_blank" rel="noreferrer" className={anchor}>{children}</a>
      : <Link href={href} className={anchor}>{children}</Link>,
    table: ({ children }) => (
      <div className="-mx-4 my-5 overflow-x-auto border-y border-neutral-200 sm:mx-0 sm:rounded-xl sm:border dark:border-neutral-800">
        <table className="w-full border-collapse text-left text-[13px] sm:text-[13.5px]">{children}</table>
      </div>
    ),
    thead: ({ children }) => <thead className="bg-neutral-50 text-neutral-900 dark:bg-neutral-900 dark:text-white">{children}</thead>,
    th: ({ children }) => <th className="whitespace-nowrap border-b border-neutral-200 px-3 py-2.5 font-medium sm:px-4 dark:border-neutral-800">{children}</th>,
    td: ({ children }) => <td className="border-b border-neutral-100 px-3 py-2.5 align-top text-neutral-700 sm:px-4 dark:border-neutral-900 dark:text-neutral-300">{children}</td>,
    hr: () => <hr className="my-8 border-neutral-200 dark:border-neutral-800" />,
    img: ({ src = '', alt = '' }) => (
      <img src={typeof src === 'string' ? src : ''} alt={alt} className="my-5 rounded-xl border border-neutral-200 dark:border-neutral-800" />
    ),
  }
}
