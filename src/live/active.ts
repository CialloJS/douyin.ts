import { err } from '../error.js'
import { api, site } from '../session/codes.js'
import type { Http } from '../session/http.js'
import type { OnlineItem, ReadSwitchItem } from '../types.js'

/** active/update:im 活跃心跳上报（登录后打一次即可，成功即静默） */
export async function heartbeat (http: Http): Promise<void> {
  const res = await http.json<{ status_code?: number }>(
    `${site.edge}${api.activeUpdate}`,
    { headers: { Referer: site.web } },
  )
  if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data)
}

/** active/status:批量查 sec 用户在线状态（source 透传，缺省 heartbeat） */
export async function onlineStatus (
  http: Http,
  secUserIds: string[],
  source = 'heartbeat',
): Promise<OnlineItem[]> {
  const form = new URLSearchParams({
    conv_ids: '[]',
    sec_user_ids: JSON.stringify(secUserIds),
    source,
  })
  const res = await http.json<{
    data?: Array<{ sec_user_id?: string; last_active_time?: number }>
  }>(
    `${site.web}${api.activeStatus}`,
    {
      method: 'POST',
      headers: { Referer: site.web, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    },
  )
  return (res.data?.data ?? []).map(item => ({
    secUserId: String(item.sec_user_id ?? ''),
    lastActiveTime: Number(item.last_active_time ?? 0),
  }))
}

/** active/config/get:查询在线状态开关（1=开启，我可被对方看到在线） */
export async function activeSwitch (http: Http): Promise<number> {
  const res = await http.json<{ status_switch?: number }>(
    `${site.web}${api.activeConfig}`,
    { headers: { Referer: site.web } },
  )
  return Number(res.data?.status_switch ?? 0)
}

/** msg_read_switch:标记一批消息已读（会话侧收件箱收到 50013 的依据；source 固定 msg_tab） */
export async function readSwitch (http: Http, items: ReadSwitchItem[]): Promise<void> {
  const res = await http.json<{
    msg_ids_resp?: Array<{ msg_id?: string; err_code?: number }>
  }>(
    `${site.web}${api.readSwitch}`,
    {
      method: 'POST',
      headers: { Referer: site.web, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        msg_ids: items.map(it => ({
          msg_id: it.msgId,
          conv_id: it.convId,
          conv_short_id: it.convShortId,
          create_time: it.createTime,
          conv_type: it.convType,
        })),
        is_retry: false,
        source: 'msg_tab',
      }),
    },
  )
  const failed = (res.data?.msg_ids_resp ?? []).find(r => Number(r.err_code ?? 0) !== 0)
  if (failed) return err(res.data)
}
