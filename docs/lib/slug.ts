/** 标题 → 锚点：保留中日韩字符，其余按 GitHub 风格折叠 */
export function slugify (text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/[\s]+/g, '-')
    .replace(/[!-/:-@[-`{-~]/g, '')
}

/** 从 MDX 源提取二级标题，供右侧本页目录使用 */
export function headingsOf (source: string): Array<{ id: string; text: string }> {
  const result: Array<{ id: string; text: string }> = []
  for (const line of source.split('\n')) {
    const match = /^##\s+(.+?)\s*$/.exec(line)
    if (match?.[1]) result.push({ id: slugify(match[1]), text: match[1] })
  }
  return result
}
