import { createHash } from 'node:crypto';

export function md5Hex(data: string | Buffer): string {
  return createHash('md5').update(data).digest('hex');
}

// 抖音 cronet 侧实测：x-ss-stub = MD5(解压后明文 body) 的大写值
export function ssStub(body: string | Buffer): string {
  return md5Hex(body).toUpperCase();
}
