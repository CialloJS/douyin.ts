import { api, site } from '../session/codes.js'
import { fingerprintParams } from '../live/transport.js'
import { err } from '../error.js'
import type { Http } from '../session/http.js'
import type { GroupShareInput, GroupShareResult } from '../types.js'

// www.douyin.com 域同接口被风控拦截（HTTP 200 返回非 JSON），imdesktop 域可用

interface ShareResponse {
  status_code?: number
  status_message?: string
  data?: Record<string, unknown>
}

function str (source: Record<string, unknown> | undefined, key: string): string {
  return typeof source?.[key] === 'string' ? String(source[key]) : ''
}

/** 解析邀请链接的 secret 与 group_id；纯 secret 直接使用 */
function parseShare (input: GroupShareInput): { secret: string; groupId: string } {
  const raw = input.share.trim()
  let secret = raw
  let groupId = input.conversationId ?? ''
  if (/^https?:\/\//.test(raw)) {
    const params = new URL(raw).searchParams
    // 分享链接里 secret/group_token、group_id/conversation_id 两种命名并存
    secret = params.get('secret') ?? params.get('group_token') ?? secret
    groupId = input.conversationId ?? params.get('group_id') ?? params.get('conversation_id') ?? ''
  }
  if (!secret || !groupId) return err({ secret, groupId })
  return { secret, groupId }
}

/**
 * 用群邀请 secret 换群邀请凭证：/aweme/v1/web/im_group_api/share/verification/。
 * 实证该接口回读群资料，且返回的 ticket 即传入的 secret（同值 AAED 串），
 * 与 610 会话详情下发的 ticket 是两条不同的串
 */
export async function verifyShare (http: Http, input: GroupShareInput): Promise<GroupShareResult> {
  const { secret, groupId } = parseShare(input)
  const params = fingerprintParams(http.deviceId, http.guid)
  params.set('iid', http.installId)
  const body = new URLSearchParams({
    ext: JSON.stringify({ group_reserve_v2_ab: '2', join_source: '5' }),
    group_id: groupId,
    invite_card_scene: String(input.scene ?? 0),
    secret,
    secret_type: '4',
  }).toString()
  const res = await http.request(`${site.im}${api.shareVerify}?${params}`, {
    method: 'POST',
    body,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Referer: `${site.im}/chat` },
  })
  // 上游失败按原文交回，解析失败时才冒泡原生异常
  if (!res.ok) return err(res.data)
  // 16+ 位整数包成字符串再 parse：conversation_short_id/owner_id 等 19 位大整数超出 Number 精度
  const raw = JSON.parse(res.data.replace(/"(\w+)"\s*:\s*(\d{16,})/g, '"$1":"$2"')) as ShareResponse
  // 该域把校验体直接铺在 data 上（status_code 为群审核态，如 7535 仍带完整数据）
  const detail = raw.data
  if (!detail || str(detail, 'ticket') === '') return err(raw)
  const owner = detail['group_owner_info'] as Record<string, unknown> | undefined
  return {
    ticket: str(detail, 'ticket'),
    conversationId: str(detail, 'conversation_id') || groupId,
    conversationShortId: str(detail, 'conversation_short_id'),
    name: str(detail, 'group_name'),
    desc: str(detail, 'group_desc'),
    ...(str(detail, 'group_avatar') ? { avatar: str(detail, 'group_avatar') } : {}),
    memberCount: Number(detail['group_member_count'] ?? 0),
    ...(str(owner, 'owner_id') ? { ownerUid: str(owner, 'owner_id') } : {}),
    ...(str(owner, 'sec_owner_id') ? { ownerSecUid: str(owner, 'sec_owner_id') } : {}),
    ...(str(owner, 'owner_name') ? { ownerNickname: str(owner, 'owner_name') } : {}),
    ...(str(detail, 'inviter_id') ? { inviterUid: str(detail, 'inviter_id') } : {}),
    ...(str(detail, 'inviter_sec_uid') ? { inviterSecUid: str(detail, 'inviter_sec_uid') } : {}),
    ...(str(detail, 'group_audit_question') ? { auditQuestion: str(detail, 'group_audit_question') } : {}),
  }
}
