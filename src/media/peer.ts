import { site, ver } from '../session/codes.js'
import { err } from '../error.js'
import type { Http } from '../session/http.js'
import type { GetPeerRequest, GetPeerResult } from '../types.js'

/** vc-gate-edge get_peer:按文件信息调度 CDN 传输节点（Result 字段映射为 camelCase） */
export async function getPeer (
  http: Http,
  req: GetPeerRequest,
): Promise<GetPeerResult> {
  const res = await http.json<{
    Result?: {
      status?: number
      fid?: string
      trace_id?: string
      req_id?: string
      token?: string
      nodes?: unknown[]
      multi_nodes?: unknown[] | null
      index_num?: number
      country_code?: number
      isp_code?: number
    }
  }>(site.peer, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      app_id: req.appId ?? ver.webAid,
      sid: req.sid ?? 5,
      task_type: req.taskType ?? 1,
      file_info: req.fileInfo,
    }),
  })
  const result = res.data?.Result
  if (!result) err(res.data)
  return {
    status: result.status ?? -1,
    fid: result.fid ?? '',
    traceId: result.trace_id ?? '',
    reqId: result.req_id ?? '',
    token: result.token ?? '',
    nodes: result.nodes ?? [],
    ...(result.multi_nodes != null ? { multiNodes: result.multi_nodes } : {}),
    indexNum: result.index_num ?? 0,
    countryCode: result.country_code ?? 0,
    ispCode: result.isp_code ?? 0,
  }
}
