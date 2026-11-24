/** 设备标识的生成与合并：缺字段才新生成，避免每次注册漂移出新 device_id */
import { randomBytes, randomUUID } from 'node:crypto'
import type { Ids } from './types.js'

function hex16 (): string {
  return randomBytes(8).toString('hex')
}

/** 合并已有标识并补全本地随机字段；服务端字段（device_id 等）保持为空直到注册 */
export function fill (base: Partial<Ids> = {}): Ids {
  const now = Math.floor(Date.now() / 1000)
  return {
    device_id: base.device_id ?? '',
    iid: base.iid ?? '',
    cdid: base.cdid ?? randomUUID(),
    clientudid: base.clientudid ?? randomUUID(),
    openudid: base.openudid ?? hex16(),
    klink_egdi: base.klink_egdi ?? '',
    device_token: base.device_token ?? '',
    req_id: base.req_id ?? randomUUID(),
    oaid: base.oaid ?? '0'.repeat(64),
    first_install: base.first_install ?? now - 7 * 86400,
    new_user: base.new_user,
    device_id_str: base.device_id_str,
    install_id_str: base.install_id_str,
    dtrait_pk1: base.dtrait_pk1,
    dtrait_pk2: base.dtrait_pk2,
    dtrait_pk1_version: base.dtrait_pk1_version,
    dtrait_pk2_version: base.dtrait_pk2_version,
    dtrait_token: base.dtrait_token,
    dtrait_version: base.dtrait_version,
    bind_dtrait: base.bind_dtrait,
    device_dtrait: base.device_dtrait,
    device_dtrait_token: base.device_dtrait_token,
    client_key: base.client_key,
    cookie: base.cookie,
    source: base.source,
  }
}
