import type { ForwardNode, RecvBody } from '../types.js'
import { objectValue, stringArray } from './value.js'

/** 按 messageType 分派的载荷解析；不适用时返回 undefined，交由通用字段推断 */
type Parse = (value: Record<string, unknown>, text: string) => RecvBody | undefined

function audio (value: Record<string, unknown>, text: string): RecvBody {
  const resource = objectValue(value['resource_url'])
  return {
    type: 'audio', text,
    audio: { urls: stringArray(resource?.['url_list']), uri: String(resource?.['uri'] ?? '') },
  }
}

function file (value: Record<string, unknown>): RecvBody {
  return {
    type: 'file', text: String(value['name'] ?? ''),
    file: { uri: String(value['uri'] ?? ''), skey: String(value['skey'] ?? ''), md5: String(value['md5'] ?? ''), name: String(value['name'] ?? ''), dataSize: Number(value['data_size'] ?? 0) },
  }
}

/** 通话状态/一起看邀请：hint 即展示文本 */
function hint (value: Record<string, unknown>): RecvBody {
  return { type: 'text', text: String(value['hint'] ?? '') }
}

/** 系统引导模板（如开启消息通知）：无内容价值，置空文本由分发层过滤 */
function guide (value: Record<string, unknown>): RecvBody | undefined {
  const aweType = Number(value['aweType'] ?? value['awe_type'] ?? 0)
  return aweType === 133 ? { type: 'text', text: '' } : undefined
}

function link (value: Record<string, unknown>): RecvBody {
  return {
    type: 'link', text: String(value['title'] ?? ''),
    link: { url: String(value['link_url'] ?? ''), title: String(value['title'] ?? ''), description: String(value['desc'] ?? ''), coverUrl: String(value['cover_url'] ?? '') },
  }
}

function userCard (value: Record<string, unknown>): RecvBody {
  const coverArr = value['cover_url'] as { url_list?: unknown[] }[] | undefined
  return {
    type: 'userCard', text: String(value['name'] ?? ''),
    user: {
      uid: String(value['uid'] ?? ''),
      secUid: String(value['secUID'] ?? ''),
      name: String(value['name'] ?? ''),
      avatarUrl: stringArray(objectValue(value['avatar'])?.['url_list'])[0] ?? '',
      ...(value['desc'] !== undefined && value['desc'] !== '' ? { desc: String(value['desc']) } : {}),
      ...(value['follower_count'] !== undefined ? { followerCount: String(value['follower_count']) } : {}),
      ...(Array.isArray(value['cover_items']) && value['cover_items'].length ? { coverItems: stringArray(value['cover_items']) } : {}),
      ...(Array.isArray(coverArr) && coverArr.length
        ? { coverUrls: coverArr.map(c => stringArray(c.url_list)?.[0] ?? '').filter(Boolean) }
        : {}),
    },
  }
}

/** 作品分享（messageType=8/77，或类型缺省时按 aweType=800 判定） */
export function shareOf (value: Record<string, unknown>, text: string): RecvBody {
  const title = String(value['content_title'] ?? '')
  const cover = objectValue(value['cover_url'])
  const coverUrl = cover ? stringArray(cover['url_list'])[0] ?? String(cover['uri'] ?? '') : ''
  return {
    type: 'share', text: text || title,
    share: {
      itemId: String(value['itemId'] ?? ''),
      title,
      uid: String(value['uid'] ?? ''),
      ...(value['secUID'] ? { secUid: String(value['secUID']) } : {}),
      ...(value['content_name'] ? { authorName: String(value['content_name']) } : {}),
      ...(coverUrl ? { coverUrl } : {}),
    },
  }
}

function forward (value: Record<string, unknown>): RecvBody {
  const summary = Array.isArray(value['list_content']) ? value['list_content'] : []
  const refs = Array.isArray(value['msg_ids']) ? value['msg_ids'] : []
  const refById = new Map(refs.map(ref => [String(ref?.['msg_id'] ?? ''), ref as Record<string, unknown>]))
  const nodes: ForwardNode[] = []
  for (const item of summary) {
    const msgId = String(item?.['msgid'] ?? '')
    const ref = refById.get(msgId)
    nodes.push({
      uid: String(ref?.['uid'] ?? ''),
      nickname: String(item?.['nick_name'] ?? ''),
      text: String(item?.['text'] ?? ''),
      msgType: Number(ref?.['msg_type'] ?? 0),
      aweType: Number(ref?.['awe_type'] ?? 0),
      msgId,
      ...(ref?.['sec_uid'] ? { secUid: String(ref['sec_uid']) } : {}),
      ...(ref?.['create_time'] ? { createTime: Number(ref['create_time']) } : {}),
    })
  }
  return { type: 'forward', text: '', nodes }
}

/** 接龙（群内多人接力登记项）：push_detail 即官方展示文本，describe 为标题 */
function chains (value: Record<string, unknown>): RecvBody {
  const items = Array.isArray(value['chains_entry_list']) ? value['chains_entry_list'] : []
  return {
    type: 'chains',
    text: String(value['push_detail'] ?? value['chains_description'] ?? ''),
    chains: {
      id: String(value['chains_id'] ?? ''),
      description: String(value['chains_description'] ?? ''),
      isStart: Number(value['is_start_chains']) === 1,
      entries: items.map((item) => {
        const it = item as Record<string, unknown>
        return { uid: String(it['e_c_u'] ?? ''), text: String(it['e_t'] ?? '') }
      }),
    },
  }
}

/** 互动卡（messageType=110）：im_dynamic_patch 为卡片载荷，raw_data 是双层转义 JSON，description(=push_detail) 即展示文本。引导卡(aweType=110402/msg_guide)与打卡卡(110372/msg_preview)的 raw_data 布局不同，平铺字段各取首段候选回退 */
function card (value: Record<string, unknown>): RecvBody {
  const patch = objectValue(value['im_dynamic_patch'])
  const raw = typeof patch?.['raw_data'] === 'string'
    ? objectValue(JSON.parse(patch['raw_data']))
    : undefined
  const pick = (...names: string[]): string => {
    for (const name of names) {
      const node = objectValue(raw?.[name])
      const cell = node?.['content']
      const hit = Array.isArray(cell) ? cell[0] : cell
      if (typeof hit === 'string' && hit) return hit
    }
    return ''
  }
  // 打卡卡 patch.id 是嵌套 JSON 字符串 {"id":..,"sign":..}，取内层 id；引导卡用 card_id
  let cardId = String(patch?.['card_id'] ?? '')
  if (!cardId && typeof patch?.['id'] === 'string') {
    const nested = objectValue(JSON.parse(patch['id']))
    cardId = String(nested?.['id'] ?? '')
  }
  return {
    type: 'card',
    text: String(value['description'] ?? value['push_detail'] ?? ''),
    card: {
      key: String(patch?.['card_key'] ?? ''),
      type: String(patch?.['card_type'] ?? ''),
      id: cardId,
      aweType: Number(value['aweType'] ?? 0),
      title: pick('content_middle_top', 'content_top'),
      desc: pick('content_middle_content', 'content_middle'),
      button: pick('bottom', 'bottom_right'),
      coverUrl: pick('content_left', 'content_bottom'),
      sign: String(patch?.['sign'] ?? ''),
      patch: patch ?? {},
    },
  }
}

/** 位置消息（messageType=502，POI 定位）：坐标 + 地点名/地址，封面为 cover_info.resource_url */
function location (value: Record<string, unknown>): RecvBody {
  const cover = objectValue(objectValue(value['cover_info'])?.['resource_url'])
  return {
    type: 'location',
    text: String(value['poi_name'] ?? value['poi_address'] ?? ''),
    location: {
      name: String(value['poi_name'] ?? ''),
      address: String(value['poi_address'] ?? ''),
      latitude: Number(value['latitude'] ?? 0),
      longitude: Number(value['longitude'] ?? 0),
      poiId: String(value['poi_id'] ?? ''),
      awemePoiId: String(value['aweme_poi_id'] ?? ''),
      uri: String(cover?.['uri'] ?? ''),
      urlList: stringArray(cover?.['url_list']),
    },
  }
}

/** 群聊邀请卡（messageType=58）：aweme_invite_card 为载荷，title 即展示文本 */
function groupCard (value: Record<string, unknown>): RecvBody {
  const card = objectValue(value['aweme_invite_card'])
  const icon = objectValue(card?.['group_icon'])
  return {
    type: 'groupCard',
    text: String(value['title'] ?? value['push_detail'] ?? ''),
    groupCard: {
      conversationId: String(card?.['conversation_id'] ?? ''),
      groupName: String(card?.['group_name'] ?? ''),
      iconUrl: stringArray(icon?.['url_list'])[0] ?? '',
      ...(card?.['group_member_count'] !== undefined ? { memberCount: Number(card['group_member_count']) } : {}),
      ...(card?.['group_owner_uid'] ? { ownerUid: String(card['group_owner_uid']) } : {}),
      ...(card?.['sec_group_owner_uid'] ? { ownerSecUid: String(card['sec_group_owner_uid']) } : {}),
      ...(card?.['group_owner_nickname'] ? { ownerNickname: String(card['group_owner_nickname']) } : {}),
      fromUid: String(card?.['from_uid'] ?? ''),
      ...(card?.['sec_from_uid'] ? { fromSecUid: String(card['sec_from_uid']) } : {}),
      // 收卡即带凭证，回传时服务端才能校验派发
      ...(card?.['ticket'] ? { ticket: String(card['ticket']) } : {}),
    },
  }
}

/** 群系统消息（messageType=1001）：文案在 locale_resources/template，渲染出可读文本而非丢给 unknown */
function system (value: Record<string, unknown>): RecvBody | undefined {
  const text = systemMessageText(value)
  return text ? { type: 'text', text } : undefined
}

/** 系统消息占位用户（active_users/passive_users）：取昵称，缺昵称回退 uid */
function placeholderUsers (value: unknown): string[] {
  if (!Array.isArray(value)) return []
  const names: string[] = []
  for (const item of value) {
    const record = objectValue(item)
    const name = String(record?.['nickname'] ?? record?.['nick_name'] ?? record?.['uid'] ?? '')
    if (name) names.push(name)
  }
  return names
}

/**
 * 群系统消息文案：服务端只下发模板，正文在 locale_resources（zh 优先）、回退 template，
 * {0}/{1} 占位按 active_users→passive_users 顺序填昵称
 */
function systemMessageText (value: Record<string, unknown>): string {
  const resources = (Array.isArray(value['locale_resources']) ? value['locale_resources'] : [])
    .map(objectValue)
    .filter((item): item is Record<string, unknown> => item !== undefined)
  const localized = (resources.find(item => String(item['lang'] ?? '').startsWith('zh')) ?? resources[0])?.['text']
  const template = typeof localized === 'string' && localized
    ? localized
    : typeof value['template'] === 'string' ? value['template'] : ''
  if (!template) return ''
  const users = [...placeholderUsers(value['active_users']), ...placeholderUsers(value['passive_users'])]
  return template.replace(/\{(\d+)\}/g, (slot, index: string) => users[Number(index)] ?? slot)
}

export const parsers = new Map<number, Parse>([
  [1, guide],
  [6, file],
  [8, shareOf],
  [17, audio],
  [25, userCard],
  [26, link],
  [58, groupCard],
  [73, hint],
  [77, shareOf],
  [90, hint],
  [110, card],
  [136, forward],
  [150, file],
  [152, chains],
  [502, location],
  [1001, system],
])
