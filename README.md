# douyin.ts

抖音 IM 开发 SDK。TypeScript 7 · 纯 ESM · Node ≥ 20。

完整文档：<https://CialloJS.github.io/douyin.ts/>

支持：扫码登录（含短信/密码/滑块等二次验证）、WS 收消息、HTTP 发消息、富媒体上传、表情、好友/群管理、会话状态与群事件。

## 安装

```bash
pnpm add douyin.ts
# 或 npm install douyin.ts
```

## 快速开始

```ts
import { login, Bot } from 'douyin.ts'

// 1. 扫码登录：二维码串交给调用方渲染，二次验证通过回调交付
const session = await login({
  onQr: qr => renderQr(qr.url),
  onStatus: s => console.log(s),
  onVerifyUrl: url => open(url),
  onMfa: async info => getCode(info),
})

// 2. 用会话构造 Bot（已有 Cookie 时也可 new Bot({ cookie }) 直接接入）
const bot = new Bot(session)

bot.on('message', async msg => {
  if (msg.type === 'text' && msg.text === 'hi') {
    await bot.msg.send(msg.chatId, { text: 'hello' })
  }
})

// 3. 启动长连
await bot.start()
```

## 会话持久化

`login` 不做任何落盘，`session.cookie` 是唯一凭据。重启后复用同一 Cookie 可免扫码：

```ts
import { writeFile, readFile } from 'node:fs/promises'

await writeFile('session.json', JSON.stringify(session))

// 下次直接加载；Cookie 失效时回到 login 重新扫码
const session = JSON.parse(await readFile('session.json', 'utf8'))
const bot = new Bot(session)
await bot.start()
```

## 消息模型

`bot.on('message')` 的 `msg` 是平铺的消息体（`InboundMessage = PushMessage & RecvBody`），按 `msg.type` 判别：

| 类型 | 说明 |
|------|------|
| `text` | 文本（`text`、`ats`、`atAll`） |
| `image` / `video` / `file` / `audio` / `emoji` | 媒体，对应字段是可直接回传 `send` 的资源 |
| `share` / `userCard` / `forward` / `link` / `chains` / `card` / `groupCard` / `location` | 各类卡片与合并转发 |
| `unknown` | 未建模类型，原文在 `raw` |

媒体消息的 `text` 只保留内容原生文案，无文案时为空字符串，不预填「[视频]」等占位；展示时按 `type` 自行处理。

```ts
bot.on('message', async msg => {
  switch (msg.type) {
    case 'text':  return bot.msg.send(msg.chatId, { text: `你说：${msg.text}` })
    case 'image': return bot.msg.send(msg.chatId, { text: '收到一张图' })
    case 'video': return bot.msg.send(msg.chatId, { text: '收到一个视频' })
    default:      return bot.msg.send(msg.chatId, { text: `收到 ${msg.type}` })
  }
})
```

## 事件

统一 `bot.on(event, fn)`：

| 事件 | 载荷 | 说明 |
|------|------|------|
| `message` | `BotMessage` | 新消息（含 `chatId`） |
| `message:edited` | `BotMessage` | 消息被编辑 |
| `notice` | `NoticeEvent` | 会话变更通知，按 `type` 细分 |
| `request` | `RequestEvent` | 好友/入群申请 |
| `voip` | `VoipCallEvent` | 语音来电 |
| `read` | `ReadEvent` | 单聊已读回执 |
| `status` | `StatusEvent` | 高频会话状态 |
| `reconnecting` / `close` | `WsReconnectEvent` / `WsCloseEvent` | 连接生命周期 |

`notice` 子类型：`group.member-increase` / `group.member-decrease` / `group.admin` / `group.name-change` / `group.avatar-change` / `group.dismiss` / `friend.increase` / `friend.decrease` / `message.recall` / `message.reaction` / `conversation.delete` / `conversation.read` / `conversation.typing` / `im.command` …

```ts
bot.on('notice', async notice => {
  if (notice.type === 'group.member-increase') {
    console.log(`群 ${notice.conversationId} 加入 ${notice.members.map(m => m.uid).join(', ')}`)
  }
})
```

## API（统一 `bot.域.动作`）

| 域 | 动作 |
|----|------|
| msg | send / reply / edit / recall / react / read / sendTyping / call |
| media | image / video / file / videoUrl / awemeDetail / getPeer / emojiList |
| sticker | list / favs / gifs / collect / trending / strategy / privacyImage |
| frd | list / requests / approve / reject |
| grp | list / members / addMembers / removeMembers / requests / approve / reject / rename / leave / create / verifyShare |
| chat | history / userMessageStat / ack / readSwitch / strangers / list / info / strangerConversations / delete / readIndex / minIndex / batchReadIndex / setting |
| user | self / account / beatToken / info / profileScene / profileOther / profileSelf / onlineStatus / heartbeat / activeSwitch |
| social | spotlight / familiar / follow / bubble |
| watch | danmaku / progress / series / mix / history / safety |
| notice | count / list |
| setting | desktop / account / compliance |

```ts
await bot.msg.send(chatId, { text: 'hi' })

const img = await bot.media.image(data)
await bot.msg.send(chatId, { image: img, text: '看这个' })

await bot.msg.reply(chatId, msg, '收到')
await bot.msg.recall(chatId, msg.serverMessageId)
```

## 错误模型

失败统一抛 `SdkError`，动态内容只在 `data` 里，`message` 恒为 `'sdk'`：

```ts
import { isErr } from 'douyin.ts'

try {
  await bot.msg.send(chatId, { text: 'hi' })
} catch (e) {
  if (isErr(e)) {
    // 上游失败：e.data 是上游响应体；前置校验：e.data 是 { 字段 }；网络失败：原生 fetch 错误
  }
}
```

SDK 不做错误码映射、不做文案拼接、不重命名字段。

## 配置

```ts
new Bot({
  cookie: string          // 登录 Cookie（login 返回或已登录浏览器复制）
  userId?: string         // 自身数字 uid，省略时 start() 自动获取
  userAgent?: string      // 默认桌面 UA
  timeout?: number        // 请求超时毫秒，默认 30000
  selfMessage?: boolean   // 自身消息是否也下发 message 事件
  device?: Device         // 已持久化的设备身份，注入后跳过重复注册
  log?: Log               // 自定义日志，默认内置彩色日志
})
```

## 致谢 / Credits

本项目参考了 `https://github.com/zhinjs/douyin-im` 的实现思路，感谢原作者的工作。
