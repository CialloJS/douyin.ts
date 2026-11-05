import type { Metadata } from 'next'
import fs from 'node:fs/promises'
import path from 'node:path'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { content } from '@/content'
import { allDocs, docOf, sectionOf, siblings } from '@/lib/nav'
import { headingsOf } from '@/lib/slug'
import { SiteHeader } from '@/components/site-header'
import { MobileToc } from '@/components/mobile-toc'
import { Sidebar } from '@/components/sidebar'
import { Toc } from '@/components/toc'

export const dynamicParams = false

export function generateStaticParams (): Array<{ slug: string[] }> {
  return allDocs()
    .filter(doc => content[doc.slug])
    .map(doc => ({ slug: doc.slug.split('/') }))
}

export async function generateMetadata ({ params }: { params: Promise<{ slug: string[] }> }): Promise<Metadata> {
  const { slug } = await params
  const doc = docOf(slug.join('/'))
  return doc ? { title: doc.title, description: doc.summary } : {}
}

export default async function DocPage ({ params }: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await params
  const key = slug.join('/')
  const doc = docOf(key)
  const loader = content[key]
  if (!doc || !loader) notFound()

  const { default: Body } = await loader()
  const source = await fs.readFile(path.join(process.cwd(), 'content', doc.file), 'utf8')
  const headings = headingsOf(source)
  const section = sectionOf(key)
  const { prev, next } = siblings(key)

  return (
    <>
      <SiteHeader />
      <div className="mx-auto flex w-full max-w-[1320px] gap-6 px-4 lg:gap-10">
        <Sidebar />
        <main className="min-w-0 flex-1 py-6 sm:py-8">
          <MobileToc title={doc.title} section={section?.title} headings={headings} />
          {section && (
            <p className="mb-2 hidden text-[11px] font-semibold uppercase tracking-widest text-neutral-400 md:block">{section.title}</p>
          )}
          <Body />
          <nav className="mt-12 grid gap-3 border-t border-neutral-200 pt-6 sm:mt-14 sm:grid-cols-2 dark:border-neutral-800">
            {prev
              ? (
                <Link href={`/docs/${prev.slug}`} className="group rounded-xl border border-neutral-200 px-4 py-3 transition-colors hover:border-neutral-400 dark:border-neutral-800 dark:hover:border-neutral-600">
                  <span className="text-xs text-neutral-400">上一篇</span>
                  <p className="mt-0.5 text-sm font-medium group-hover:text-[var(--color-brand)]">{prev.title}</p>
                </Link>
              )
              : <span className="hidden sm:block" />}
            {next && (
              <Link href={`/docs/${next.slug}`} className="group rounded-xl border border-neutral-200 px-4 py-3 transition-colors hover:border-neutral-400 sm:text-right dark:border-neutral-800 dark:hover:border-neutral-600">
                <span className="text-xs text-neutral-400">下一篇</span>
                <p className="mt-0.5 text-sm font-medium group-hover:text-[var(--color-brand)]">{next.title}</p>
              </Link>
            )}
          </nav>
        </main>
        <Toc headings={headings} />
      </div>
    </>
  )
}
