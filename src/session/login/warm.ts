/** imdesktop 域 ttwid 预热:官方客户端冷启动向同域 ttwid 服务领取 ttwid,缺失时确认轮触发 2156/2046 */
import { im, passport } from '../sign/const.js'
import type { Http } from '../http.js'
import { fld, path } from './codes.js'

export async function warm (http: Http): Promise<void> {
  await http.request(`${im.origin}${path.ttwid}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ aid: Number(passport.aid), service: fld.service }),
  })
}
