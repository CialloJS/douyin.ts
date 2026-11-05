import type { ComponentType } from 'react'

/** MDX 页面清单：新增文档时需同时登记这里与 lib/nav.ts（静态分析要求字面量路径） */
export const content: Record<string, () => Promise<{ default: ComponentType }>> = {
  guide: () => import('./guide/index.mdx'),
  'guide/login': () => import('./guide/login.mdx'),
  'guide/message': () => import('./guide/message.mdx'),
  'guide/error': () => import('./guide/error.mdx'),
  'guide/config': () => import('./guide/config.mdx'),
  'events/message': () => import('./events/message.mdx'),
  'events/notice': () => import('./events/notice.mdx'),
  'events/request': () => import('./events/request.mdx'),
  'events/voip': () => import('./events/voip.mdx'),
  'events/read': () => import('./events/read.mdx'),
  'events/status': () => import('./events/status.mdx'),
  'events/connection': () => import('./events/connection.mdx'),
  'api/msg': () => import('./api/msg.mdx'),
  'api/media': () => import('./api/media.mdx'),
  'api/sticker': () => import('./api/sticker.mdx'),
  'api/frd': () => import('./api/frd.mdx'),
  'api/grp': () => import('./api/grp.mdx'),
  'api/chat': () => import('./api/chat.mdx'),
  'api/user': () => import('./api/user.mdx'),
  'api/social': () => import('./api/social.mdx'),
  'api/watch': () => import('./api/watch.mdx'),
  'api/notice': () => import('./api/notice.mdx'),
  'api/setting': () => import('./api/setting.mdx'),
}
