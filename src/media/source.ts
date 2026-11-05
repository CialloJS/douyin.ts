import { readFile } from 'node:fs/promises'
import { err } from '../error.js'
import type { MediaInput } from '../types.js'

/** 输入是否是「待上传的源」；对象型输入已是资产，直接透传 */
export const isInput = (v: unknown): v is MediaInput =>
  typeof v === 'string' || v instanceof Uint8Array || v instanceof ArrayBuffer

/**
 * 只解析不识别：字节原样返回，字符串依次尝试读文件、抓 URL、按 base64 解码。
 * 单一格式不认识时不提前判定，解析全部失败才把原始输入交回。
 */
export async function resolveMedia (input: MediaInput): Promise<Uint8Array> {
  if (input instanceof Uint8Array) return input
  if (input instanceof ArrayBuffer) return new Uint8Array(input)
  try {
    return await readFile(input)
  } catch {
    // 不是可读路径，继续尝试下一种
  }
  try {
    const res = await fetch(input)
    if (res.ok) return new Uint8Array(await res.arrayBuffer())
  } catch {
    // 不是可抓取 URL，继续尝试下一种
  }
  const raw = input.replace(/^base64:\/\//i, '').replace(/\s/g, '')
  const bytes = Buffer.from(raw, 'base64')
  if (bytes.length > 0) return bytes
  return err({ input })
}

/** 文件名只从路径/URL 尾部取；取不到就用调用方缺省值 */
export function fileNameOf (input: MediaInput): string {
  if (typeof input !== 'string') return 'file'
  const last = input.split(/[?#]/)[0]!.split(/[\\/]/).pop() ?? ''
  return last || 'file'
}
