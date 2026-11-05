/** 文档导航：slug 即 /docs/<slug> 的路由，file 指向 MDX 源文件 */
export interface Doc {
  slug: string
  file: string
  title: string
  summary: string
}

export interface Section {
  title: string
  lead: string
  docs: Doc[]
}

const guide: Doc[] = [
  { slug: 'guide', file: 'guide/index.mdx', title: '快速开始', summary: '安装、登录、收发第一条消息' },
  { slug: 'guide/login', file: 'guide/login.mdx', title: '登录', summary: '扫码、二次验证与会话持久化' },
  { slug: 'guide/message', file: 'guide/message.mdx', title: '消息与事件', summary: '内容类型、发送与事件分发' },
  { slug: 'guide/error', file: 'guide/error.mdx', title: '错误处理', summary: 'SdkError 的四种来源' },
  { slug: 'guide/config', file: 'guide/config.mdx', title: '配置', summary: 'BotOpts、日志与超时' },
]

const events: Doc[] = [
  { slug: 'events/message', file: 'events/message.mdx', title: 'message', summary: '新消息与消息编辑' },
  { slug: 'events/notice', file: 'events/notice.mdx', title: 'notice', summary: '会话变更通知' },
  { slug: 'events/request', file: 'events/request.mdx', title: 'request', summary: '好友与入群申请' },
  { slug: 'events/voip', file: 'events/voip.mdx', title: 'voip', summary: '语音来电' },
  { slug: 'events/read', file: 'events/read.mdx', title: 'read', summary: '单聊已读回执' },
  { slug: 'events/status', file: 'events/status.mdx', title: 'status', summary: '高频会话状态' },
  { slug: 'events/connection', file: 'events/connection.mdx', title: 'connection', summary: '连接生命周期' },
]

const api: Doc[] = [
  { slug: 'api/msg', file: 'api/msg.mdx', title: 'msg', summary: '发送、回复、撤回、表情回应' },
  { slug: 'api/media', file: 'api/media.mdx', title: 'media', summary: '图片、视频、文件与视频地址' },
  { slug: 'api/sticker', file: 'api/sticker.mdx', title: 'sticker', summary: '表情资源、收藏与推荐' },
  { slug: 'api/frd', file: 'api/frd.mdx', title: 'frd', summary: '好友列表与申请' },
  { slug: 'api/grp', file: 'api/grp.mdx', title: 'grp', summary: '群列表、成员与群管理' },
  { slug: 'api/chat', file: 'api/chat.mdx', title: 'chat', summary: '会话列表、历史与设置' },
  { slug: 'api/user', file: 'api/user.mdx', title: 'user', summary: '自身资料与他人资料' },
  { slug: 'api/social', file: 'api/social.mdx', title: 'social', summary: '关注、粉丝与关系' },
  { slug: 'api/watch', file: 'api/watch.mdx', title: 'watch', summary: '视频播放与观看记录' },
  { slug: 'api/notice', file: 'api/notice.mdx', title: 'notice', summary: '通知列表与未读数' },
  { slug: 'api/setting', file: 'api/setting.mdx', title: 'setting', summary: '账号与消息设置' },
]

export const sections: Section[] = [
  { title: '指南', lead: '从安装到第一条消息', docs: guide },
  { title: '事件', lead: 'bot.on(event, fn)', docs: events },
  { title: 'API', lead: 'bot.域.动作', docs: api },
]

export function allDocs (): Doc[] {
  return sections.flatMap(s => s.docs)
}

export function docOf (slug: string): Doc | undefined {
  return allDocs().find(d => d.slug === slug)
}

/** 上一篇/下一篇按导航顺序串联 */
export function siblings (slug: string): { prev?: Doc; next?: Doc } {
  const docs = allDocs()
  const index = docs.findIndex(d => d.slug === slug)
  if (index < 0) return {}
  return { prev: docs[index - 1], next: docs[index + 1] }
}

export function sectionOf (slug: string): Section | undefined {
  return sections.find(s => s.docs.some(d => d.slug === slug))
}
