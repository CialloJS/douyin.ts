'use client'

import { useEffect, useState } from 'react'
import { Moon, Sun } from 'lucide-react'
import { Button } from '@heroui/react'

/** 主题保存在 localStorage；首屏由 layout 内联脚本先行切换 */
export function ThemeToggle () {
  const [dark, setDark] = useState(false)

  useEffect(() => {
    setDark(document.documentElement.classList.contains('dark'))
  }, [])

  const toggle = (): void => {
    const next = !document.documentElement.classList.contains('dark')
    document.documentElement.classList.toggle('dark', next)
    localStorage.setItem('theme', next ? 'dark' : 'light')
    setDark(next)
  }

  return (
    <Button isIconOnly size="sm" variant="ghost" aria-label="切换主题" className="h-10 w-10 md:h-9 md:w-9" onPress={toggle}>
      {dark ? <Sun size={17} strokeWidth={1.8} /> : <Moon size={17} strokeWidth={1.8} />}
    </Button>
  )
}

