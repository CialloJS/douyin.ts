import type {
  Card,
  FileAsset,
  GroupCard,
  ImageAsset,
  ImageFormat,
  LocationCard,
  ShareItem,
  UserCard,
} from '../types.js'

export function buildImageContent (image: {
  oid: string
  skey: string
  md5: string
  dataSize: number
  width: number
  height: number
  format?: ImageFormat
}): string {
  return JSON.stringify({
    resource_url: {
      oid: image.oid,
      skey: image.skey,
      data_size: image.dataSize,
      md5: image.md5,
    },
    cover_height: image.height,
    cover_width: image.width,
    check_pics: [],
    md5: image.md5,
    from_gallery: 1,
    aweType: image.format === 'gif' ? 2703 : 2702,
  })
}

/** 文件消息 content（messageType=6，aweType=15001，字段与官方接收样例同形） */
export function buildFileContent (file: FileAsset): string {
  return JSON.stringify({
    aweType: 15001,
    uri: file.uri,
    skey: file.skey,
    md5: file.md5,
    name: file.name,
    data_size: file.dataSize,
    format: file.name.includes('.') ? file.name.split('.').pop()!.toLowerCase() : '',
    createdAt: 0,
    is_card: false,
    msgHint: '',
  })
}

export function buildVideoContent (video: {
  tkey: string
  skey: string
  md5: string
  poster?: ImageAsset
  width?: number
  height?: number
  checkPics?: string[]
}): string {
  return JSON.stringify({
    video: { tkey: video.tkey, md5: video.md5, skey: video.skey },
    ...(video.poster ? { poster: { oid: video.poster.oid, md5: video.poster.md5, skey: video.poster.skey } } : {}),
    ...(video.width !== undefined ? { width: video.width } : {}),
    ...(video.height !== undefined ? { height: video.height } : {}),
    check_pics: video.checkPics ?? [],
  })
}

/** 作品分享卡片 content（messageType=8 / aweType=800，结构对齐 Android 分享帧），share_id 首段为自己的 uid */
export function buildShareContent (item: ShareItem, senderUid: string): string {
  const image = (uri: string): object => ({
    data_size: 0,
    height: 720,
    uri,
    url_list: [uri],
    width: 540,
  })
  return JSON.stringify({
    aweType: 800,
    awemeType: 0,
    content_name: item.authorName ?? '',
    content_title: item.title ?? item.itemId,
    ...(item.coverUrl
      ? { cover_height: 1440, cover_url: image(item.coverUrl), cover_width: 2560 }
      : {}),
    createdAt: 0,
    is_aigc: false,
    is_card: false,
    is_hot_spot_video: false,
    is_story: false,
    itemId: item.itemId,
    item_mask_status: 0,
    msgHint: '',
    need_skip_strange: 0,
    scene_type: 0,
    ...(item.secUid ? { secUID: item.secUid } : {}),
    share_id: `${senderUid}_${Date.now()}_${item.itemId}`,
    share_with_timestamp: -1,
    uid: item.uid,
  })
}

/** 用户名片卡片 content（messageType=25 / aweType=0，结构对齐 Android 名片帧）；uid 与 secUid 须真实，服务端可能据 uid 重建 */
export function buildUserCardContent (item: UserCard): string {
  return JSON.stringify({
    ...(item.avatarUrl
      ? { avatar: { data_size: 0, height: 0, uri: item.avatarUrl, url_list: [item.avatarUrl], width: 0 } }
      : {}),
    aweType: 0,
    createdAt: 0,
    ...(item.coverItems?.length ? { cover_items: item.coverItems } : {}),
    ...(item.coverUrls?.length
      ? { cover_url: item.coverUrls.map(url => ({ data_size: 0, height: 0, uri: '', url_list: [url], width: 0 })) }
      : {}),
    ...(item.desc ? { desc: item.desc } : {}),
    ...(item.followerCount ? { follower_count: item.followerCount } : {}),
    is_card: false,
    is_secret: false,
    msgHint: '',
    name: item.name ?? '',
    push_detail: item.name ?? '',
    ...(item.secUid ? { secUID: item.secUid } : {}),
    source: 'private_chat',
    uid: item.uid,
  })
}

/** 构造互动卡 content（messageType=110）：description/push_detail 即展示文本，patch 原样回填，aweType 还原接收值 */
export function buildCardContent (card: Card, title: string): string {
  return JSON.stringify({
    aweType: card.aweType || 110402,
    im_dynamic_patch: card.patch,
    description: title,
    push_detail: title,
  })
}

/** 构造表情消息 content（messageType=5 / lite_emoji）：字段与官方发送样本逐一同形（含 aweType:507、url.width:0）；url 必须传 im-resource 域直链，tos-cn 表态域会被服务端注入 s:visible 导致仅自身可见 */
export function buildEmojiContent (url: string, displayName = '[表情]'): string {
  return JSON.stringify({
    display_name: displayName,
    height: 100,
    width: 100,
    image_id: 0,
    image_type: 'png',
    package_id: 0,
    show_notice: false,
    resource_type: 4,
    updateConversationTime: true,
    url: { height: 0, data_size: 0, uri: url, url_list: [url], width: 0 },
    createdAt: 0,
    is_card: false,
    msgHint: '',
    aweType: 507,
  })
}

/** 构造位置消息 content（messageType=502 POI 定位）：字段与官方接收样例同形，封面用 cover_info.resource_url */
export function buildLocationContent (location: LocationCard): string {
  return JSON.stringify({
    aweType: 0,
    ...(location.awemePoiId ? { aweme_poi_id: location.awemePoiId } : {}),
    cover_info: {
      resource_url: {
        data_size: 0,
        height: 0,
        uri: location.uri ?? '',
        url_list: location.urlList ?? [],
        width: 0,
      },
    },
    createdAt: 0,
    is_card: false,
    latitude: location.latitude,
    longitude: location.longitude,
    msgHint: '',
    poi_address: location.address,
    ...(location.poiId ? { poi_id: location.poiId } : {}),
    poi_name: location.name,
  })
}

/** 构造群聊邀请卡 content（messageType=58 / aweme_invite_card）；from_uid 缺省以发送者身份填充，title/desc 参照官方文案 */
export function buildGroupCardContent (card: GroupCard, senderUid: string): string {
  const name = card.groupName
  const inviter = card.fromNickname ?? card.fromUid ?? senderUid
  return JSON.stringify({
    aweme_invite_card: {
      scene: 0,
      card_type: 1,
      ...(card.iconUrl ? { group_icon: { url_list: [card.iconUrl] } } : {}),
      group_name: name,
      ...(card.memberCount !== undefined ? { group_member_count: card.memberCount } : {}),
      conversation_id: card.conversationId,
      conversation_short_id: card.conversationId,
      ...(card.ownerNickname ? { group_owner_nickname: card.ownerNickname } : {}),
      from_uid: card.fromUid ?? senderUid,
      ...(card.fromSecUid ? { sec_from_uid: card.fromSecUid } : {}),
      group_create_type: '0',
      need_cut_icon: 1,
      ...(card.ownerUid ? { group_owner_uid: card.ownerUid } : {}),
      ...(card.ownerSecUid ? { sec_group_owner_uid: card.ownerSecUid } : {}),
      source: 0,
      // ticket 服务端校验通过才派发；缺省(未填)仍按收卡回传形态提交
      ...(card.ticket ? { ticket: card.ticket } : {}),
    },
    title: `邀请你加入「${name}」`,
    desc: `${inviter} 邀请你加入「${name}」群聊，快来看下吧。`,
    type_desc: `${name}群聊`,
    push_detail: `邀请你加入${name}`,
  })
}
