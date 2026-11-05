import type { ReactNode } from 'react'

const tones = {
  note: 'border-sky-300/70 bg-sky-50/70 text-sky-950 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-100',
  tip: 'border-emerald-300/70 bg-emerald-50/70 text-emerald-950 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-100',
  warn: 'border-amber-300/70 bg-amber-50/70 text-amber-950 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-100',
} as const

type Tone = keyof typeof tones

function Callout ({ tone, title, children }: { tone: Tone; title: string; children: ReactNode }) {
  return (
    <div className={`my-5 rounded-xl border px-4 py-3 text-[13.5px] leading-6 ${tones[tone]}`}>
      <p className="mb-1 font-semibold">{title}</p>
      <div className="[&>p]:my-0">{children}</div>
    </div>
  )
}

export function Note ({ children }: { children: ReactNode }) {
  return <Callout tone="note" title="说明">{children}</Callout>
}

export function Tip ({ children }: { children: ReactNode }) {
  return <Callout tone="tip" title="提示">{children}</Callout>
}

export function Warn ({ children }: { children: ReactNode }) {
  return <Callout tone="warn" title="注意">{children}</Callout>
}
