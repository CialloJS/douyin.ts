/** Session 组装:uid 兜底与真实资料覆盖 */
import { err } from '../../error.js'
import { ck } from './codes.js'
import { self } from '../../contact/self.js'
import type { Http } from '../http.js'
import type { QrUserData, Session } from './types.js'

export function sessionOf (http: Http, userData?: QrUserData): Session {
  // 新版 uid_tt cookie 已是 hash 形态;frontier device_id / 消息过滤需要数字 uid
  const userId = userData?.user_id_str
    ?? (userData?.user_id != null ? String(userData.user_id) : undefined)
    ?? http.jar.get(ck.uid)
  if (!userId) err({ userId })
  const session: Session = { userId, cookie: http.jar.header() }
  if (userData) session.userData = userData
  return session
}

/** passport 的昵称/头像多为占位值,用真实资料覆盖(失败不阻断) */
export async function finalize (http: Http, session: Session): Promise<Session> {
  await self(http)
    .then(profile => {
      session.userData = {
        ...session.userData,
        ...(profile.nickname ? { screen_name: profile.nickname } : {}),
        ...(profile.avatar ? { avatar_url: profile.avatar } : {}),
      }
    })
    .catch(() => undefined)
  return session
}
