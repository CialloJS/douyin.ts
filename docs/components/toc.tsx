export interface Heading {
  id: string
  text: string
}

/** 右侧本页目录：仅列 h2，由服务端解析 MDX 源得到 */
export function Toc ({ headings }: { headings: Heading[] }) {
  if (headings.length === 0) return null
  return (
    <aside className="hidden w-44 shrink-0 xl:block">
      <nav className="sticky top-16 py-8">
        <p className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-neutral-400">本页内容</p>
        <ul className="space-y-1.5 border-l border-neutral-200 pl-3 dark:border-neutral-800">
          {headings.map(heading => (
            <li key={heading.id}>
              <a
                href={`#${heading.id}`}
                className="block text-[13px] leading-snug text-neutral-500 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white"
              >
                {heading.text}
              </a>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  )
}
