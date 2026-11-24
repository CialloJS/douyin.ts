/** App 发送编排：媒体先归一化，合并转发先注册云端记录，再交给 IM 帧发送 */
import { err } from '../error.js'
import { mergeContent, rawJson } from '../message/forward.js'
import type { ForwardNode } from '../types.js'
import type { Comm } from './comm.js'
import type { Conv, SendOpts } from './conv.js'
import type { Media } from './media.js'

export class Send {
  constructor (
    private readonly conv: Conv,
    private readonly media: Media,
    private readonly comm: Comm,
  ) {}

  async send (opts: SendOpts): Promise<Record<string, unknown>> {
    const body = opts.body
    if (body?.type === 'forward') return this.forward(opts, body.nodes)
    return this.conv.send({ ...opts, body: body ? await this.media.prepare(body) : undefined })
  }

  /** 合并转发：真实节点走 prepare 注册原消息，伪造节点直接发摘要卡（无云端记录可注册） */
  private async forward (opts: SendOpts, nodes: ForwardNode[]): Promise<Record<string, unknown>> {
    if (!nodes.length) return err({ nodes })
    if (opts.shortId === undefined) return err({ shortId: opts.shortId })
    const generated = mergeContent(nodes, opts.shortId)
    if (nodes.some(node => node.msgId === undefined)) {
      return this.conv.send({ ...opts, body: undefined, messageType: 136, content: generated })
    }
    const res = await this.comm.mergePrepare(rawJson({
      origin_conv_short_id: BigInt(opts.shortId),
      msg_id_list: nodes.map(node => BigInt(node.msgId as string)),
      generated_content: generated,
    }))
    const content = res['verified_content']
    return this.conv.send({
      ...opts,
      body: undefined,
      messageType: 136,
      content: typeof content === 'string' ? content : generated,
    })
  }
}
