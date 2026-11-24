import { constants, createCipheriv, createECDH, createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync, pbkdf2Sync, publicEncrypt, randomBytes, randomInt, randomUUID, sign } from "node:crypto";
import * as os$1 from "node:os";
import os, { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as zlib from "node:zlib";
import { gzipSync } from "node:zlib";
import protobuf from "protobufjs";
import WebSocket from "ws";
import { readFile } from "node:fs/promises";
import { Mp4Demuxer, VideoDecoder } from "@napi-rs/webcodecs";
import { Transformer } from "@napi-rs/image";
import * as https from "node:https";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { uptime } from "node:process";
import * as http from "node:http";
import { createServer } from "node:http";
//#region src/error.ts
/**
* SDK 只把错误来源原样交回，不做字段重命名、不拼描述、不映射错误码。
* 上游失败 → data 是上游响应体；前置校验 → data 是失败字段；网络失败 → data 是原生错误。
*/
var SdkError = class extends Error {
	data;
	name = "SdkError";
	constructor(data, options) {
		super("sdk", options);
		this.data = data;
	}
};
function err(data, options) {
	throw new SdkError(data, options);
}
function isErr(value) {
	return value instanceof SdkError;
}
//#endregion
//#region src/session/sign/const.ts
/** Passport 域常量：passport = 登录链路（imdesktop 桌面端内嵌登录页），im = 桌面 IM 链路（imdesktop），web = 创作者网页链路（creator.douyin.com） */
/**
* 桌面客户端统一按 macOS 口径伪装（对齐 douyin-im darwin 分支）：
* 硬件注册、登录页 UA、IM query、风控参数共用同一套值，避免平台/版本互相矛盾触发更严的风控
*/
const mac = {
	release: "24.6.0",
	model: "Mac14,6",
	platform: "darwin",
	channel: "20002",
	/** 内嵌登录页 UA（douyin-im DESKTOP_LOGIN_USER_AGENT） */
	loginUa: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) douyinim/1.2.1 Chrome/130.0.6723.58 Electron/33.2.0-rs.21.release.main.1 Safari/537.36",
	/** IM 数据域/媒体上传 UA（douyin-im services/im/desktop.ts） */
	ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) douyinim/1.2.1 Chrome/130.0.6723.58 Electron/33.2.0 Safari/537.36",
	/** 硬件画像与请求指纹共用同一分辨率/浏览器口径 */
	screen: "1707x1067",
	width: "1707",
	height: "1067",
	browserPlatform: "MacIntel",
	browserName: "Mozilla"
};
/**
* 桌面客户端内嵌登录页链路（imdesktop.douyin.com 实证）：
* 登录与 IM 同域同 aid，扫码产出 aid=339757 会话，直接用于 IM 数据域
*/
const passport = {
	origin: "https://imdesktop.douyin.com",
	aid: "339757",
	appKey: "3c452fb664e3de0e936108429a0bc697",
	ua: mac.loginUa
};
const im = {
	origin: "https://imdesktop.douyin.com",
	aid: "339757",
	version: "1.2.1",
	appKey: "3c452fb664e3de0e936108429a0bc697"
};
const web = {
	origin: "https://creator.douyin.com",
	aid: "2906",
	appKey: "6ddd3ec693f3a124adb29b91b244ece5"
};
/** 桌面设备注册与上报路径 */
const reg$1 = {
	channel: "local_test",
	path: "/service/2/desktop/device_register/",
	alert: "/service/2/app_alert/"
};
/** desktop lite Passport 公共 query 固定值 */
const lite = {
	jssdk: "5.1.2",
	type: "lite",
	authn: "1.0.0.428-web",
	lang: "zh",
	appLang: "zh-CN",
	fromSdk: "1",
	fromSaas: "1",
	newLogin: "1",
	platform: "PC",
	iid: "0"
};
/** 复用的响应头名 */
const hdr = {
	verify: "x-tt-verify-passport-decision",
	log: "x-tt-logid",
	captcha: "x-vc-bdturing-parameters"
};
//#endregion
//#region src/session/sign/aid.ts
function hmacSha256Hex(key, message) {
	return createHmac("sha256", Buffer.from(key)).update(Buffer.from(message)).digest("hex");
}
function hexToBytes(hex) {
	const normalized = hex.length % 2 === 1 ? `0${hex}` : hex;
	return Uint8Array.from(Buffer.from(normalized, "hex"));
}
/** 272.js `Nl`：首包 HMAC 后按轮扩展为 32 字节（内层 `e` 固定为首包 hex） */
function deriveSignKey(password, salt, extra, length = 32) {
	let pw = password;
	if (pw.length === 0) pw = /* @__PURE__ */ new Uint8Array(32);
	const firstHex = hmacSha256Hex(pw, salt);
	const fixedKey = hexToBytes(firstHex);
	let rollingHex = firstHex;
	const out = [];
	for (let round = 1; out.length < length; round += 1) {
		rollingHex = hmacSha256Hex(fixedKey, Uint8Array.from([
			...hexToBytes(rollingHex),
			...extra,
			round
		]));
		out.push(...hexToBytes(rollingHex));
	}
	return Uint8Array.from(out.slice(0, length));
}
/**
* `x-tt-passport-aid-sign`（64 hex HMAC-SHA256）
* 消息：`aid={aid}&path={path}&ts={ts}`
*/
function aidSign(input) {
	const appKey = input.appKey ?? web.appKey;
	const ts = input.ts ?? "";
	const enc = new TextEncoder();
	const key = deriveSignKey(enc.encode(ts), enc.encode(appKey), /* @__PURE__ */ new Uint8Array(0), 32);
	const message = `aid=${input.aid}&path=${input.path}&ts=${ts}`;
	return hmacSha256Hex(key, enc.encode(message));
}
/** SSO 域名下给 path 加 `/passport/sso` 前缀；创作者站通常原样返回 */
function normalizePassportPath(path, hostname = "creator.douyin.com") {
	if (path.startsWith("/passport") || hostname.includes("sso")) return path;
	return `/passport/sso${path}`;
}
/** Passport 查询串 `ts`：当日 UTC 12:00:00 的 Unix 秒（与 tt-account-sdk aid-sign 中间件一致） */
function noonTs(date = /* @__PURE__ */ new Date()) {
	const noon = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), 12, 0, 0, 0);
	return String(Math.floor(noon / 1e3));
}
//#endregion
//#region src/session/sign/bogus.ts
/**
* Web 端 a_bogus（bdms）逆向算法，自参考实现 a_bogus.js V 1.0.1.20 逐行等价迁移。
* 禁止改动任何常量表与位运算，否则签名失效。
*/
const TABLES = {
	s0: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
	s1: "Dkdpgh4ZKsQB80/Mfvw36XI1R25+WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=",
	s2: "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=",
	s3: "ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzmFjJnryx9HVGDaStCe",
	s4: "Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe"
};
const SALT = "dhzx";
const PRESETS = {
	"1.0.1.20": {
		constVal1: 22740,
		constVal2: 2631
	},
	"1.0.1.16": {
		constVal1: 22740,
		constVal2: 2631
	}
};
/** 与 UA（Mac）匹配的屏参 */
const SCREEN$1 = "1728|1117|1728|303|1728|1117|1728|982|MacIntel";
function aBogus(options) {
	const preset = PRESETS[options.bdmsPreset ?? "1.0.1.16"];
	const body = options.body ?? "";
	const fpArr = strToByteArr(options.screenFingerprint ?? SCREEN$1);
	const tm2 = (/* @__PURE__ */ new Date()).getTime() - 1;
	const tm1Before = (/* @__PURE__ */ new Date()).getTime();
	const queryArr32 = sm3Digest(sm3Digest(`${options.query}${SALT}`));
	const dataArr32 = sm3Digest(sm3Digest(`${body}${SALT}`));
	const keyVal = options.keyVal ?? 0;
	const userAgentArr32 = sm3Digest(lmStrEncode(strToByteArr(rc4Parse(String.fromCharCode(...[
		.00390625,
		1,
		keyVal
	]), options.userAgent)), TABLES.s3));
	const tm1 = (/* @__PURE__ */ new Date()).getTime();
	const arr50 = [
		41,
		9,
		6,
		tm1 - tm1Before + 3 & 255,
		tm1 >> 0 & 255,
		tm1 >> 8 & 255,
		tm1 >> 16 & 255,
		tm1 >> 24 & 255,
		tm1 / 256 / 256 / 256 / 256 & 255,
		tm1 / 256 / 256 / 256 / 256 / 256 & 255,
		1,
		Math.floor(1 / 256) & 255,
		129,
		0,
		(Math.random() * 200 | 0) + 50,
		(Math.random() * 200 | 0) + 50,
		(Math.random() * 200 | 0) + 50,
		(Math.random() * 200 | 0) + 50,
		keyVal >> 0 & 255,
		keyVal >> 8 & 255,
		keyVal >> 16 & 255,
		keyVal >> 24 & 255,
		queryArr32[9],
		queryArr32[18],
		queryArr32[3],
		dataArr32[10],
		dataArr32[19],
		dataArr32[4],
		userAgentArr32[11],
		userAgentArr32[21],
		userAgentArr32[5],
		tm2 >> 0 & 255,
		tm2 >> 8 & 255,
		tm2 >> 16 & 255,
		tm2 >> 24 & 255,
		tm2 / 256 / 256 / 256 / 256 & 255,
		tm2 / 256 / 256 / 256 / 256 / 256 & 255,
		3,
		preset.constVal1 >> 0 & 255,
		preset.constVal1 >> 8 & 255,
		preset.constVal1 >> 16 & 255,
		preset.constVal1 >> 24 & 255,
		preset.constVal2 >> 0 & 255,
		preset.constVal2 >> 8 & 255,
		preset.constVal2 >> 16 & 255,
		preset.constVal2 >> 24 & 255,
		44,
		0,
		4,
		0
	];
	const newArr50 = reorderArr50(arr50);
	const xorRandomArr8 = xorRandomArr8Gen();
	const xorArray = xorFold([...xorRandomArr8, ...arr50]);
	const arr4Merge = [
		...newArr50,
		...fpArr,
		...tmArr(tm1),
		...xorArray
	];
	let aBogusLmStr = String.fromCharCode(...aBogusPrefix4());
	const mergeArr = [];
	for (let i = 0; i < arr4Merge.length / 3; i++) {
		const val1 = arr4Merge[3 * i];
		const val2 = arr4Merge[3 * i + 1];
		const val3 = arr4Merge[3 * i + 2];
		const randomVal = Math.random() * 1e3 & 255;
		mergeArr.push(randomVal & 145 | val1 & 110, randomVal & 66 | val2 & 189, randomVal & 44 | val3 & 211, val1 & 145 | val2 & 66 | val3 & 44);
	}
	const bigArr = [
		...xorRandomArr8,
		...mergeArr,
		...xorArray
	];
	aBogusLmStr += rc4Parse(String.fromCharCode(211), String.fromCharCode(...bigArr));
	return lmStrEncode(strToByteArr(aBogusLmStr), TABLES.s4);
}
/** jumpbyte-bot internal/abogus 的逐步骤移植，仅供 desktop Passport 使用 */
function aBogusDesktop(options) {
	const now = options.nowMs ?? Date.now();
	const random = options.random ?? cryptoRandomFloat;
	const query = `${options.query}${SALT}`;
	const body = `${options.body ?? ""}${SALT}`;
	const queryHash = sm3Digest(sm3Digest(query));
	const bodyHash = sm3Digest(sm3Digest(body));
	const uaHash = sm3Digest(lmStrEncode(garble(uaSbox(0), encodeUtf8ForSm3(options.userAgent)), TABLES.s3));
	const fixed = encodeUtf8ForSm3("784|943|1707|1019|1707|1019|1707|1067|MacIntel");
	const dateBucket = Math.trunc((now - 17218368e5) / 12096e5);
	const firstTime = now;
	const secondTime = firstTime - Math.trunc(random() * 10);
	const prefix = randomPrefix(random);
	const arr = new Array(55).fill(0);
	arr[0] = 41;
	arr[1] = dateBucket;
	arr[2] = 5;
	arr[3] = firstTime - secondTime + 3 & 255;
	for (let i = 0; i < 6; i++) arr[4 + i] = byteAt(firstTime, i);
	arr[10] = 1;
	arr[12] = 1;
	arr[14] = 1;
	arr[22] = queryHash[9];
	arr[23] = queryHash[18];
	arr[24] = 3;
	arr[25] = queryHash[3];
	arr[26] = bodyHash[10];
	arr[27] = bodyHash[19];
	arr[28] = 4;
	arr[29] = bodyHash[4];
	arr[30] = uaHash[11];
	arr[31] = uaHash[21];
	arr[32] = 5;
	arr[33] = uaHash[5];
	for (let i = 0; i < 6; i++) arr[34 + i] = byteAt(secondTime, i);
	arr[40] = 3;
	writeInt32LE(arr, 41, 6241);
	writeInt32LE(arr, 45, 6383);
	const lastTime = encodeUtf8ForSm3(`${firstTime + 3 & 255},`);
	arr[49] = fixed.length;
	arr[50] = fixed.length & 255;
	arr[51] = fixed.length >> 8 & 255;
	arr[52] = lastTime.length;
	arr[53] = lastTime.length & 255;
	arr[54] = lastTime.length >> 8 & 255;
	const checksumIndexes = [
		0,
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		12,
		13,
		14,
		15,
		16,
		17,
		18,
		19,
		20,
		21,
		22,
		23,
		25,
		26,
		27,
		29,
		30,
		31,
		33,
		34,
		35,
		36,
		37,
		38,
		39,
		40,
		41,
		42,
		43,
		44,
		45,
		46,
		47,
		48,
		50,
		51,
		53,
		54
	];
	let checksum = prefix.reduce((value, item) => value ^ item, 0);
	for (const index of checksumIndexes) checksum ^= arr[index];
	const payload = expand3(prefix, [
		...[
			9,
			18,
			30,
			35,
			47,
			4,
			44,
			19,
			10,
			23,
			12,
			40,
			25,
			42,
			3,
			22,
			38,
			21,
			5,
			45,
			1,
			29,
			6,
			43,
			33,
			14,
			36,
			37,
			2,
			46,
			15,
			48,
			31,
			26,
			16,
			13,
			8,
			41,
			27,
			17,
			39,
			20,
			11,
			0,
			34,
			7,
			50,
			51,
			53,
			54
		].map((index) => arr[index]),
		...fixed,
		...lastTime,
		checksum
	], random);
	const header = abHeader(random);
	const encrypted = garble(abSbox(), payload);
	return lmStrEncode([...header, ...encrypted], TABLES.s4);
}
function expand3(prefix, input, random) {
	const output = [...prefix];
	for (let i = 0; i < input.length; i += 3) {
		if (i + 2 >= input.length) {
			output.push(...input.slice(i));
			break;
		}
		const value = Math.trunc(random() * 1e3) & 255;
		const first = input[i];
		const second = input[i + 1];
		const third = input[i + 2];
		output.push(value & 145 | first & 110, value & 66 | second & 189, value & 44 | third & 211, first & 145 | second & 66 | third & 44);
	}
	return output;
}
function abHeader(random) {
	const first = Math.trunc(random() * 65535) & 255;
	const second = Math.trunc(random() * 40);
	return [
		first & 170 | 1,
		first & 85 | 2,
		second & 170 | 80,
		second & 85 | 2
	];
}
function randomPrefix(random) {
	const first = Math.trunc(random() * 65535);
	const low = first & 255;
	const high = first >> 8 & 255;
	const second = Math.trunc(random() * 240);
	const third = Math.trunc(random() * 255) & 77 | 178;
	return [
		low & 170 | 1,
		low & 85 | 0,
		high & 170 | 0,
		high & 85 | 0,
		second & 170 | 1,
		second & 85 | 0,
		third & 170 | 0,
		third & 85 | 0
	];
}
function abSbox() {
	return sbox([211]);
}
function uaSbox(salt) {
	return sbox([
		0,
		1,
		salt
	]);
}
function sbox(key) {
	const values = Array.from({ length: 256 }, (_, index) => 255 - index);
	let previous = 0;
	for (let i = 0; i < 256; i++) {
		previous = (previous * values[i] + previous + key[i % key.length]) % 256;
		[values[i], values[previous]] = [values[previous], values[i]];
	}
	return values;
}
function garble(box, input) {
	let previous = 0;
	return input.map((value, index) => {
		const cursor = (index + 1) % 256;
		previous = (previous + box[cursor]) % 256;
		const old = box[cursor];
		box[cursor] = box[previous];
		box[previous] = old;
		return value ^ box[(box[cursor] + old) % 256];
	});
}
function byteAt(value, index) {
	return Number(BigInt(Math.trunc(value)) >> BigInt(index * 8) & 255n);
}
function writeInt32LE(target, offset, value) {
	for (let i = 0; i < 4; i++) target[offset + i] = value >> i * 8 & 255;
}
function cryptoRandomFloat() {
	const value = randomBytes(8).readBigUInt64BE() >> 11n;
	return Number(value) / 9007199254740992;
}
function lmStrEncode(bytes, table) {
	let out = "";
	const groupNum = bytes.length / 3;
	for (let i = 0; i < groupNum; i++) {
		const b1 = bytes[3 * i] & 255;
		const b2 = bytes[3 * i + 1] & 255;
		const b3 = bytes[3 * i + 2] & 255;
		const big = b1 << 16 | b2 << 8 | b3;
		out += table.charAt((big & 16515072) >> 18);
		out += table.charAt((big & 258048) >> 12);
		out += table.charAt((big & 4032) >> 6);
		out += table.charAt(big & 63);
	}
	const rem = bytes.length % 3;
	if (rem === 1) out = out.substring(0, out.length - 2) + "==";
	else if (rem === 2) out = out.substring(0, out.length - 1) + "=";
	return out;
}
function rc4Parse(key, data) {
	const sbox = Array.from({ length: 256 }, (_, i) => 255 - i);
	let j = 0;
	for (let i = 0; i < 256; i++) {
		j = (j * sbox[i] + j + key.charCodeAt(i % key.length)) % 256;
		const tmp = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = tmp;
	}
	let out = "";
	let prev = 0;
	for (let i = 0; i < data.length; i++) {
		const idx = (i + 1) % 256;
		const idx2 = (prev + sbox[idx]) % 256;
		const idx3 = (sbox[idx2] + sbox[idx]) % 256;
		prev = idx2;
		const t1 = sbox[idx];
		sbox[idx] = sbox[idx2];
		sbox[idx2] = t1;
		out += String.fromCharCode(data.charCodeAt(i) ^ sbox[idx3]);
	}
	return out;
}
function strToByteArr(s) {
	return Array.from(s, (c) => c.charCodeAt(0));
}
function tmArr(tm) {
	return strToByteArr(`${tm + 3 & 255},`);
}
function aBogusPrefix4() {
	const r1 = Math.random() * 65535 & 255;
	const r2 = Math.random() * 40;
	return [
		r1 & 170 | 1,
		r1 & 85 | 2,
		r2 >> 0 & 170 | 80,
		r2 >> 0 & 85 | 2
	];
}
function xorRandomArr8Gen() {
	const r1 = Math.random() * 65535;
	const t1 = r1 & 255;
	const t2 = r1 >> 8 & 255;
	const n1 = t1 & 170 | 1;
	const n2 = t1 & 85 | 0;
	const n3 = t2 & 170 | 0;
	const n4 = t2 & 85 | 0;
	const randomVal = Math.random() * 255;
	let isEven = Math.random() * 240 + 110;
	if (isEven % 2 !== 0) isEven++;
	return [
		n1,
		n2,
		n3,
		n4,
		isEven & 170 | 1,
		isEven & 85 | 0,
		(randomVal >> 0 & 77 | 178) & 170 | 16,
		(randomVal >> 0 & 77 | 176) & 85 | 2
	];
}
function reorderArr50(arr50) {
	const o = new Array(50);
	o[0] = arr50[9];
	o[1] = arr50[18];
	o[2] = arr50[28];
	o[3] = arr50[32];
	o[4] = arr50[11];
	o[5] = arr50[4];
	o[6] = arr50[11];
	o[7] = arr50[11];
	o[8] = arr50[9];
	o[9] = arr50[23];
	o[10] = arr50[12];
	o[11] = arr50[37];
	o[12] = arr50[24];
	o[13] = arr50[39];
	o[14] = arr50[3];
	o[15] = arr50[22];
	o[16] = arr50[35];
	o[17] = arr50[11];
	o[18] = arr50[5];
	o[19] = arr50[42];
	o[20] = arr50[1];
	o[21] = arr50[27];
	o[22] = arr50[33];
	o[23] = arr50[11];
	o[24] = arr50[30];
	o[25] = arr50[14];
	o[26] = arr50[6];
	o[27] = arr50[7];
	o[28] = arr50[2];
	o[29] = arr50[43];
	o[30] = arr50[15];
	o[31] = arr50[11];
	o[32] = arr50[29];
	o[33] = arr50[25];
	o[34] = arr50[16];
	o[35] = arr50[11];
	o[36] = arr50[8];
	o[37] = arr50[38];
	o[38] = arr50[26];
	o[39] = arr50[17];
	o[40] = arr50[9];
	o[41] = arr50[11];
	o[42] = arr50[11];
	o[43] = arr50[0];
	o[44] = arr50[31];
	o[45] = arr50[7];
	o[46] = arr50[46];
	o[47] = arr50[47];
	o[48] = arr50[48];
	o[49] = arr50[49];
	return o;
}
function xorFold(arr) {
	let x = 0;
	for (const v of arr) x ^= v;
	return [x];
}
function sm3Digest(data) {
	const bytes = typeof data === "string" ? encodeUtf8ForSm3(data) : data;
	return new Sm3().sum(bytes);
}
function encodeUtf8ForSm3(text) {
	const encoded = encodeURIComponent(text).replace(/%([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
	return Array.from(encoded, (c) => c.charCodeAt(0));
}
var Sm3 = class {
	reg = [];
	chunk = [];
	size = 0;
	reset() {
		this.reg = [
			1937774191,
			1226093241,
			388252375,
			3666478592,
			2842636476,
			372324522,
			3817729613,
			2969243214
		];
		this.chunk = [];
		this.size = 0;
	}
	write(data) {
		this.size += data.length;
		let r = 64 - this.chunk.length;
		if (data.length < r) {
			this.chunk = this.chunk.concat(data);
			return;
		}
		this.chunk = this.chunk.concat(data.slice(0, r));
		while (this.chunk.length >= 64) {
			this.compressBlock(this.chunk);
			if (r < data.length) this.chunk = data.slice(r, Math.min(r + 64, data.length));
			else this.chunk = [];
			r += 64;
		}
	}
	sum(data) {
		this.reset();
		if (data.length) this.write(data);
		this.fill();
		for (let i = 0; i < this.chunk.length; i += 64) this.compressBlock(this.chunk.slice(i, i + 64));
		const out = new Array(32);
		for (let i = 0; i < 8; i++) {
			let c = this.reg[i];
			out[4 * i + 3] = c & 255;
			c >>>= 8;
			out[4 * i + 2] = c & 255;
			c >>>= 8;
			out[4 * i + 1] = c & 255;
			c >>>= 8;
			out[4 * i] = c & 255;
		}
		this.reset();
		return out;
	}
	fill() {
		const bitLen = 8 * this.size;
		let e = this.chunk.push(128) % 64;
		for (; 64 - e < 8; e -= 64);
		for (; e < 56; e++) this.chunk.push(0);
		for (let i = 0; i < 4; i++) {
			const n = Math.floor(bitLen / 4294967296);
			this.chunk.push(n >>> 8 * (3 - i) & 255);
		}
		for (let i = 0; i < 4; i++) this.chunk.push(bitLen >>> 8 * (3 - i) & 255);
	}
	compressBlock(block) {
		const w = expand(block);
		const r = this.reg.slice();
		for (let j = 0; j < 64; j++) {
			let o = rotl(r[0], 12) + r[4] + rotl(tj(j), j);
			o = rotl((o & 4294967295) >>> 0, 7);
			const i = ((o ^ rotl(r[0], 12)) & 4294967295) >>> 0;
			let u = ff(j, r[0], r[1], r[2]) + r[3] + i + w[j + 68] & 4294967295;
			u >>>= 0;
			let c = gg(j, r[4], r[5], r[6]) + r[7] + o + w[j] & 4294967295;
			c >>>= 0;
			r[3] = r[2];
			r[2] = rotl(r[1], 9);
			r[1] = r[0];
			r[0] = u;
			r[7] = r[6];
			r[6] = rotl(r[5], 19);
			r[5] = r[4];
			r[4] = (c ^ rotl(c, 9) ^ rotl(c, 17)) >>> 0;
		}
		for (let a = 0; a < 8; a++) this.reg[a] = (this.reg[a] ^ r[a]) >>> 0;
	}
};
function rotl(x, n) {
	n %= 32;
	return (x << n | x >>> 32 - n) >>> 0;
}
/** 与参考 a_bogus.js / bdms 内嵌 SM3 一致（非国标 Tj 低段常量） */
function tj(j) {
	return j < 16 ? 2043430169 : 2055708042;
}
function ff(j, a, b, c) {
	return j < 16 ? (a ^ b ^ c) >>> 0 : (a & b | a & c | b & c) >>> 0;
}
function gg(j, a, b, c) {
	return j < 16 ? (a ^ b ^ c) >>> 0 : (a & b | ~a & c) >>> 0;
}
function expand(block) {
	const w = new Array(132).fill(0);
	for (let i = 0; i < 16; i++) w[i] = (block[4 * i] << 24 | block[4 * i + 1] << 16 | block[4 * i + 2] << 8 | block[4 * i + 3]) >>> 0;
	for (let i = 16; i < 68; i++) {
		let t = w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15);
		t = (t ^ rotl(t, 15) ^ rotl(t, 23)) >>> 0;
		w[i] = (t ^ rotl(w[i - 13], 7) ^ w[i - 6]) >>> 0;
	}
	for (let i = 0; i < 64; i++) w[i + 68] = (w[i] ^ w[i + 4]) >>> 0;
	return w;
}
//#endregion
//#region src/session/sign/qs.ts
function sortedParamString(obj, keepFirstN) {
	let keys = Object.keys(obj).sort();
	if (keepFirstN !== void 0 && keepFirstN >= 0) keys = keys.slice(0, keepFirstN);
	return {
		str: keys.map((k) => {
			const v = obj[k];
			return `${k}=${typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}`;
		}).join("&"),
		keys
	};
}
/** qs：对「排序后前 10 个 query 键名」逗号拼接，再 UTF-8 + 每字节 XOR 5 → hex（无补零） */
function encodeQsKeyNames(keyNames) {
	const input = keyNames.join(",");
	const out = [];
	for (let i = 0; i < input.length; i++) {
		const cp = input.charCodeAt(i);
		const bytes = [];
		if (cp >= 0 && cp <= 127) bytes.push(cp);
		else if (cp >= 128 && cp <= 2047) bytes.push(192 | 31 & cp >> 6, 128 | 63 & cp);
		else if (cp >= 2048 && cp <= 55295 || cp >= 57344 && cp <= 65535) bytes.push(224 | 15 & cp >> 12, 128 | 63 & cp >> 6, 128 | 63 & cp);
		for (const b of bytes) out.push((5 ^ b).toString(16));
	}
	return out.join("");
}
/**
* 复现 tt-account-sdk 请求拦截器 `d(query, body, appKey)`：
* sign = sha256(排序 query 前 10 项 & body & app_key)
*/
function signQs(input) {
	const appKey = input.appKey ?? web.appKey;
	const body = input.body ?? {};
	const { str: queryStr, keys } = sortedParamString(input.query, 10);
	const { str: bodyStr } = sortedParamString(body);
	const payload = `${queryStr}&${bodyStr}&app_key=${appKey}`;
	return {
		sign: createHash("sha256").update(payload, "utf8").digest("hex"),
		qs: encodeQsKeyNames(keys)
	};
}
function randomTrace() {
	return randomBytes(4).toString("hex");
}
function signQuery(baseQuery, body = {}, extras) {
	const signInput = {
		query: baseQuery,
		body
	};
	if (extras?.appKey) signInput.appKey = extras.appKey;
	const { sign, qs } = signQs(signInput);
	return finish({
		...baseQuery,
		sign,
		qs
	}, extras);
}
/**
* 重放已签名的请求:官方验证完成后的重试只补 fp 与验证字段，
* ts/sign/qs 沿用失败那一轮；重算签名会被服务端当成新一轮请求而触发频控
*/
function resumeQuery(signed, extras) {
	const query = { ...signed };
	delete query.a_bogus;
	return finish(query, extras);
}
function finish(base, extras) {
	const query = { ...base };
	if (extras?.msToken) query.msToken = extras.msToken;
	const manualAbogus = extras?.aBogus;
	const compute = !manualAbogus && extras?.enableABogus !== false && Boolean(extras?.userAgent);
	if (manualAbogus) query.a_bogus = manualAbogus;
	else if (compute) {
		const queryForAbogus = new URLSearchParams(query).toString();
		const abOpts = {
			userAgent: extras.userAgent,
			query: queryForAbogus,
			body: extras?.bodyWire ?? ""
		};
		if (extras?.screenFingerprint) abOpts.screenFingerprint = extras.screenFingerprint;
		if (extras?.bdmsPreset) abOpts.bdmsPreset = extras.bdmsPreset;
		query.a_bogus = extras?.aBogusVariant === "jumpbyte-desktop" ? aBogusDesktop({
			userAgent: abOpts.userAgent,
			query: abOpts.query,
			body: abOpts.body ?? ""
		}) : aBogus(abOpts);
	}
	return {
		query,
		search: new URLSearchParams(query).toString()
	};
}
function encodeForm(body) {
	return Object.keys(body).map((key) => {
		const value = body[key] ?? "";
		return `${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
	}).join("&");
}
/**
* 桌面 normal SDK（2.4.12）Passport 基础查询，字段与顺序对齐官方桌面客户端抓包
* （HAR 实证：imdesktop.douyin.com / aid=339757；request_host 走 file:// 本地登录页）
*/
function passportBaseQuery(opts) {
	return {
		passport_jssdk_version: "2.4.12",
		passport_jssdk_type: "normal",
		is_from_ttaccountsdk: "1",
		aid: passport.aid,
		language: "zh",
		ts: noonTs(),
		...opts.next ? { next: opts.next } : {},
		...opts.extra ?? {},
		is_new_login: "1",
		is_from_iesaccountsaas: "1",
		account_sdk_source: "web",
		account_sdk_source_info: opts.accountSdkSourceInfo ?? "",
		p_js_v: "2.4.12",
		p_js_t: "pro",
		p_zt: "3.3.5",
		p_ver: "1.0.29",
		request_host: "file%3A%2F%2F",
		p_bd: "1.0.1.7",
		biz_trace_id: opts.bizTraceId ?? randomTrace(),
		device_id: opts.deviceId,
		iid: opts.installId,
		version_code: im.version,
		device_platform: "PC"
	};
}
/** jumpbyte desktop canonical 参数顺序（form/query 编码用） */
const DESKTOP_PARAM_ORDER = {
	passport_jssdk_version: 0,
	passport_jssdk_type: 1,
	is_from_ttaccountsdk: 2,
	aid: 3,
	language: 4,
	account_app_language: 5,
	ts: 6,
	next: 7,
	need_logo: 8,
	need_short_url: 9,
	is_new_login: 10,
	is_from_iesaccountsaas: 11,
	account_sdk_source: 12,
	account_sdk_source_info: 13,
	p_js_v: 14,
	p_js_t: 15,
	p_zt: 16,
	p_ver: 17,
	request_host: 18,
	p_bd: 19,
	biz_trace_id: 20,
	new_authn_sdk_version: 21,
	device_id: 22,
	iid: 23,
	version_code: 24,
	device_platform: 25,
	sign: 100,
	qs: 101,
	msToken: 102,
	a_bogus: 103
};
/** desktop 端 Passport 参数编码：按 jumpbyte canonical 顺序输出 form/query 串 */
function encodeDesktopParams(params) {
	return Object.keys(params).sort((left, right) => {
		const leftOrder = DESKTOP_PARAM_ORDER[left];
		const rightOrder = DESKTOP_PARAM_ORDER[right];
		if (leftOrder != null && rightOrder != null) return leftOrder - rightOrder;
		if (leftOrder != null) return -1;
		if (rightOrder != null) return 1;
		return left < right ? -1 : left > right ? 1 : 0;
	}).map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(params[key] ?? "")}`).join("&");
}
const RANDOM_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** 128 位随机 msToken（desktop lite 接口用） */
function randomMsToken(length = 128) {
	return [...randomBytes(length)].map((value) => RANDOM_ALPHABET[value & 63]).join("");
}
/** 随机 hex（desktop biz_trace_id/device_id 用） */
function randomHex(length) {
	return [...randomMsToken(length)].map((value) => "0123456789abcdef"[value.charCodeAt(0) & 15]).join("");
}
//#endregion
//#region src/session/jar.ts
/** 精简 Cookie 会话：抖音全站共享一份键值对，不区分 domain/path */
const ATTRIBUTES = /* @__PURE__ */ new Set([
	"path",
	"domain",
	"expires",
	"max-age",
	"secure",
	"httponly",
	"samesite"
]);
var Jar = class {
	store = /* @__PURE__ */ new Map();
	constructor(initial) {
		if (initial) this.merge(initial);
	}
	get(name) {
		return this.store.get(name);
	}
	has(name) {
		return this.store.has(name);
	}
	set(name, value) {
		this.store.set(name, value);
	}
	delete(name) {
		this.store.delete(name);
	}
	clear() {
		this.store.clear();
	}
	/** 导入 Cookie 请求头；响应 Set-Cookie 走 absorb 以支持过期删除 */
	merge(raw) {
		for (const part of raw.split(/[;\n]/)) {
			const eq = part.indexOf("=");
			if (eq <= 0) continue;
			const name = part.slice(0, eq).trim();
			if (name && !ATTRIBUTES.has(name.toLowerCase())) this.store.set(name, part.slice(eq + 1).trim());
		}
	}
	header() {
		return [...this.store].map(([key, value]) => `${key}=${value}`).join("; ");
	}
	/** 接受独立或合并的 Set-Cookie（容忍 Expires 中的逗号）；max-age<=0 或已过期则删除 */
	absorb(raw, now = Date.now()) {
		for (const line of raw.split(/,(?=\s*[^\s;,=]+\s*=)/)) {
			const [pair, ...attrs] = line.split(";");
			const eq = pair?.indexOf("=") ?? -1;
			if (!pair || eq <= 0) continue;
			const name = pair.slice(0, eq).trim();
			const value = pair.slice(eq + 1).trim();
			let maxAge;
			let expires;
			for (const attr of attrs) {
				const sep = attr.indexOf("=");
				if (sep < 0) continue;
				const key = attr.slice(0, sep).trim().toLowerCase();
				const val = attr.slice(sep + 1).trim();
				if (key === "max-age" && /^-?\d+$/.test(val)) maxAge = Number(val);
				if (key === "expires") expires = Date.parse(val);
			}
			if (maxAge !== void 0 ? maxAge <= 0 : expires !== void 0 && expires <= now) this.store.delete(name);
			else this.store.set(name, value);
		}
	}
};
//#endregion
//#region src/session/log.ts
const GRAY = "\x1B[90m";
const CYAN = "\x1B[36m";
const YELLOW = "\x1B[33m";
const RED = "\x1B[31m";
const RESET = "\x1B[0m";
const pad = (n) => String(n).padStart(2, "0");
function stamp() {
	const now = /* @__PURE__ */ new Date();
	return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}
/** quiet 整体关停输出；tag 区分多实例来源 */
function createLog(opts = {}) {
	if (opts.quiet) return {
		info: () => {},
		warn: () => {},
		error: () => {}
	};
	const head = opts.tag ? `${GRAY}[${opts.tag}]${RESET} ` : "";
	const line = (color, level, msg) => `${GRAY}${stamp()}${RESET} ${head}${color}${level}${RESET} ${msg}`;
	return {
		info: (msg) => console.info(line(CYAN, "info", msg)),
		warn: (msg) => console.warn(line(YELLOW, "warn", msg)),
		error: (msg) => console.error(line(RED, "error", msg))
	};
}
//#endregion
//#region src/session/http.ts
/**
* 抖音 HTTP 通道：Cookie/UA/超时封装 + Passport 请求头。
* 签名（sign/qs/a_bogus）由调用方组装进 URL 后直发，本类不感知具体接口。
*/
var Http = class {
	jar;
	userId;
	ua;
	log;
	bizTraceId;
	/** 服务端注册的桌面设备身份（登录时注入；'0' 表示未注册） */
	deviceId = "0";
	installId = "0";
	guid = randomHex(32);
	timeout;
	portrait = `${randomUUID()}.login`;
	constructor(opts = {}) {
		this.timeout = opts.timeout ?? 3e4;
		this.jar = new Jar(opts.cookie);
		this.userId = opts.userId ?? "";
		this.ua = opts.userAgent ?? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";
		this.log = opts.log ?? createLog({ tag: "http" });
		this.bizTraceId = this.jar.get("biz_trace_id") ?? randomTrace();
		this.jar.set("biz_trace_id", this.bizTraceId);
	}
	/** 注入 device_register 签发的设备身份 */
	setDevice(device) {
		this.deviceId = device.deviceId;
		this.installId = device.installId;
		this.guid = device.guid;
	}
	hasDevice() {
		return this.deviceId !== "0";
	}
	/** Passport 请求头；imdesktop（桌面，含登录）/ creator（web）分流 */
	passportHeaders(url) {
		const desktop = Boolean(url?.startsWith(im.origin));
		const login = !desktop && Boolean(url?.startsWith(passport.origin));
		const headers = {
			Accept: "application/json, text/javascript",
			Referer: desktop || login ? im.origin : `${web.origin}/creator-micro/home`
		};
		const csrf = this.jar.get("passport_csrf_token") ?? this.jar.get("passport_csrf_token_default");
		if (csrf) headers["x-tt-passport-csrf-token"] = csrf;
		headers["x-tt-passport-trace-id"] = this.bizTraceId;
		headers["x-tt-passport-verify-portrait"] = this.portrait;
		const domain = login ? "passport" : desktop ? "im" : "web";
		const sign = this.aidSignFor(url, domain);
		if (sign) headers["x-tt-passport-aid-sign"] = sign;
		if (desktop || login) return headers;
		const secsdk = this.jar.get("x-web-secsdk-uid");
		if (secsdk) headers["x-secsdk-csrf-token"] = `000100000001${secsdk.replace(/-/g, "")}`;
		return headers;
	}
	async request(url, init = {}) {
		const res = await this.send(url, init);
		const text = await res.text();
		return {
			ok: res.ok,
			status: res.status,
			headers: res.headers,
			data: text,
			text
		};
	}
	/** 只负责解码；状态与业务失败由调用方按原始响应决定如何交回 */
	async json(url, init = {}) {
		const res = await this.request(url, init);
		return {
			...res,
			data: JSON.parse(res.text)
		};
	}
	async bytes(url, init = {}) {
		const res = await this.send(url, init);
		return {
			ok: res.ok,
			status: res.status,
			headers: res.headers,
			data: new Uint8Array(await res.arrayBuffer())
		};
	}
	get(url, init = {}) {
		return this.request(url, {
			...init,
			method: "GET"
		});
	}
	/** Passport form 链路：body 已是 urlencoded 串，默认补 Content-Type */
	post(url, body = "", init = {}) {
		const headers = new Headers(init.headers);
		if (!headers.has("Content-Type")) headers.set("Content-Type", "application/x-www-form-urlencoded");
		return this.request(url, {
			...init,
			headers,
			method: "POST",
			body
		});
	}
	/** 媒体上传：body 原样透传，Content-Type 由调用方决定 */
	upload(url, body, init = {}) {
		return this.request(url, {
			...init,
			method: "POST",
			body
		});
	}
	aidSignFor(url, domain) {
		if (!url) return void 0;
		const scope = {
			passport,
			im,
			web
		}[domain];
		try {
			return aidSign({
				aid: scope.aid,
				appKey: scope.appKey,
				path: normalizePassportPath(new URL(url).pathname),
				ts: noonTs()
			});
		} catch {
			return;
		}
	}
	async send(url, init) {
		const headers = new Headers(init.headers);
		if (!headers.has("User-Agent")) headers.set("User-Agent", this.ua);
		const cookie = this.jar.header();
		if (cookie && !headers.has("Cookie")) headers.set("Cookie", cookie);
		const res = await fetch(url, {
			...init,
			headers,
			signal: init.signal ?? AbortSignal.timeout(this.timeout)
		});
		this.absorb(res.headers);
		return res;
	}
	/** 吸收 Set-Cookie 与 msToken：会话跨请求自续 */
	absorb(headers) {
		for (const line of headers.getSetCookie()) this.jar.absorb(line);
		const ms = headers.get("x-ms-token");
		if (ms) this.jar.set("msToken", ms);
	}
};
//#endregion
//#region src/session/device.ts
/**
* 桌面设备注册（对齐 douyin-im device-registration）：
* macOS 硬件画像 → /service/2/desktop/device_register/ 签发数字 device_id/install_id，
* 服务端认识设备后登录不再强制 MFA。身份只存在进程内，不落盘。
*/
const run = promisify(execFile);
/** Desktop 系统设备信息 2.0.1 / passport-util logEncrypt v3（替换+轮转，非 AES） */
const SBOX = Buffer.from("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16", "hex");
const KEY = Buffer.from("I+D&*76:j27kVH<us9&d").subarray(0, 16).map((b) => SBOX[b]);
function encodeDeviceLog(value, timestamp = Date.now()) {
	const gzip = gzipSync(Buffer.from(value), {
		level: 6,
		memLevel: 4
	});
	gzip.writeUInt32LE(Math.floor(timestamp / 1e3), 4);
	gzip[9] = 3;
	const padding = (16 - gzip.length % 16) % 16;
	const input = Buffer.concat([gzip, Buffer.alloc(padding, padding)]);
	const output = Buffer.alloc(6 + input.length);
	output.set([
		116,
		99,
		3,
		padding,
		0,
		3
	]);
	for (let base = 0; base < input.length; base += 16) for (let word = 0; word < 4; word++) for (let byte = 0; byte < 4; byte++) {
		const index = word * 4 + byte;
		output[6 + base + index] = SBOX[input[base + word * 4 + (byte + word) % 4]] ^ KEY[index];
	}
	return output;
}
/** Desktop 的 Eo(app.getGuid()) 兜底；注册成功后被服务端 DID 替换 */
function guidHash(guid) {
	let hash = 0;
	for (let index = 0; index < guid.length; index++) hash = 31 * hash + guid.charCodeAt(index) >>> 0;
	return String(hash);
}
/**
* 稳定 GUID：同一台机器每次启动一致。
* 不落盘，用硬件种子派生，注册失败回退的 DID 才不会每次漂移成「新设备」反复触发 MFA。
*/
function stableGuid(hardware) {
	return createHash("sha256").update(`${hardware.uuid}:${hardware.serial}:${hardware.model}`).digest("hex").slice(0, 32);
}
/** 非 darwin 宿主：用本机硬件种子派生稳定的 Apple 口径标识 */
function deriveMac(seed) {
	const hex = createHash("sha256").update(seed).digest("hex");
	return {
		uuid: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${(8 | parseInt(hex[16], 16) & 3).toString(16)}${hex.slice(17, 20)}-${hex.slice(20, 32)}`,
		serial: hex.slice(0, 10).toUpperCase(),
		sku: `Mac-${hex.slice(10, 26).toUpperCase()}`
	};
}
/** darwin 读 ioreg，其他宿主读 WMI 作为种子（与官方桌面客户端同源字段） */
async function readSeed() {
	if (process.platform === "darwin") {
		const { stdout } = await run("/usr/sbin/ioreg", [
			"-c",
			"IOPlatformExpertDevice",
			"-d",
			"2"
		], {
			encoding: "utf8",
			timeout: 15e3
		});
		const pick = (key) => stdout.match(new RegExp(`"${key}"\\s*=\\s*(?:"([^"]*)"|([^\\n]*))`))?.slice(1, 3).find(Boolean)?.trim() ?? "";
		const uuid = pick("IOPlatformUUID").toLowerCase();
		const serial = pick("IOPlatformSerialNumber");
		if (!uuid || !serial) err({ platform: process.platform });
		return {
			uuid,
			serial,
			model: pick("model"),
			sku: pick("board-id") || pick("target-sub-type")
		};
	}
	const { stdout } = await run("powershell.exe", [
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"$s=Get-CimInstance Win32_ComputerSystemProduct; $d=Get-CimInstance Win32_DiskDrive | Where-Object SerialNumber | Select-Object -First 1; @{model=$s.Name;uuid=$s.UUID;serial=$d.SerialNumber} | ConvertTo-Json -Compress"
	], {
		encoding: "utf8",
		timeout: 15e3,
		maxBuffer: 8388608,
		windowsHide: true
	});
	const result = JSON.parse(stdout.trim());
	const uuid = result["uuid"]?.trim() ?? "";
	const serial = result["serial"]?.trim() ?? "";
	if (!uuid || !serial) err({ platform: process.platform });
	return {
		uuid,
		serial
	};
}
/** 读取本机硬件画像；非 macOS 宿主把本机硬件种子转成 macOS 口径 */
async function readHardware() {
	let seed;
	try {
		seed = await readSeed();
	} catch {}
	const base = seed ?? {
		uuid: `${os.hostname()}:${os.userInfo().username}`,
		serial: os.arch()
	};
	const real = seed != null && process.platform === "darwin";
	const ids = real ? {
		uuid: base.uuid,
		serial: base.serial,
		sku: seed.sku ?? ""
	} : deriveMac(`${base.uuid}:${base.serial}`);
	return {
		release: real ? os.release() : mac.release,
		model: real ? seed?.model || mac.model : mac.model,
		uuid: ids.uuid,
		serial: ids.serial,
		sku: ids.sku,
		mac: Object.values(os.networkInterfaces()).flat().find((e) => e?.mac && e.mac !== "00:00:00:00:00:00")?.mac ?? "",
		resolution: mac.screen,
		timezone: (/* @__PURE__ */ new Date()).toString().split(" ")[5] ?? "",
		timezoneName: Intl.DateTimeFormat().resolvedOptions().timeZone,
		timezoneOffset: -(/* @__PURE__ */ new Date()).getTimezoneOffset() * 60,
		language: Intl.DateTimeFormat().resolvedOptions().locale
	};
}
const platformParams = (hardware) => ({
	aid: "339757",
	channel: reg$1.channel,
	os: "MacOS",
	device_platform: "MacOS",
	version_code: im.version,
	macos_uuid: hardware.uuid,
	macos_serial: hardware.serial
});
/** 构造 device_register 请求（JSON 整数字段不经 Number，保留 int64） */
function buildRegister(hardware) {
	const common = platformParams(hardware);
	const query = new URLSearchParams({
		...common,
		os_version: hardware.release,
		device_type: common["device_platform"]
	});
	const body = {
		header: {
			device_id: 0,
			install_id: 0,
			os: "MacOS",
			device_platform: "MacOS",
			sdk_version: "2.0.1",
			aid: 339757,
			mc: hardware.mac,
			channel: reg$1.channel,
			package: "com.bytedance.aweme-im-pc.desktop",
			language: hardware.language,
			app_version: im.version,
			os_version: hardware.release,
			device_model: hardware.model,
			time_zone: hardware.timezone,
			tz_name: hardware.timezoneName,
			tz_offset: hardware.timezoneOffset,
			resolution: hardware.resolution,
			app_region: "cn",
			app_language: "zh-CN",
			display_name: "抖音聊天",
			macos_uuid: hardware.uuid,
			macos_serial: hardware.serial,
			sku: hardware.sku
		},
		_gen_time: 0,
		magic_tag: "ss_app_log"
	};
	return {
		url: `${im.origin}${reg$1.path}?${query}`,
		body: encodeDeviceLog(JSON.stringify(body))
	};
}
async function register(hardware) {
	const request = buildRegister(hardware);
	const response = await fetch(request.url, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"User-Agent": "TTNetwork PC"
		},
		body: new Uint8Array(request.body),
		signal: AbortSignal.timeout(3e4)
	});
	const result = await response.json();
	if (!response.ok) err(result);
	return {
		deviceId: String(result["device_id_str"] ?? result["device_id"]),
		installId: String(result["install_id_str"] ?? result["install_id"])
	};
}
async function activate$1(hardware, device) {
	const query = new URLSearchParams({
		...platformParams(hardware),
		app_name: "抖音聊天",
		device_id: device.deviceId,
		iid: device.installId
	});
	const response = await fetch(`${im.origin}${reg$1.alert}?${query}`, {
		method: "POST",
		signal: AbortSignal.timeout(3e4)
	});
	const result = await response.json();
	if (!response.ok) err(result);
	if (result["message"] !== "success") err(result);
}
/**
* 登录前的设备生命周期（对齐 douyin-im startDeviceLifecycle）：
* 硬件注册签发 DID；未获确认回退 GUID 哈希（对齐官方兜底）。
*/
async function createDevice(log) {
	const hardware = await readHardware();
	const guid = stableGuid(hardware);
	try {
		const registered = await register(hardware);
		await activate$1(hardware, registered).catch(() => void 0);
		return {
			...registered,
			guid
		};
	} catch {
		log?.warn(`设备注册未获确认，回退 GUID 哈希 ${guidHash(guid)}`);
		return {
			deviceId: guidHash(guid),
			installId: "0",
			guid
		};
	}
}
//#endregion
//#region src/session/emitter.ts
var Emitter = class {
	map = /* @__PURE__ */ new Map();
	on(event, fn) {
		const set = this.map.get(event) ?? /* @__PURE__ */ new Set();
		set.add(fn);
		this.map.set(event, set);
	}
	off(event, fn) {
		this.map.get(event)?.delete(fn);
	}
	emit(event, ...args) {
		for (const fn of this.map.get(event) ?? []) fn(...args);
	}
};
//#endregion
//#region src/session/codes.ts
/** IM 域常量：站点、接口路径、缓存与协议固定值集中一处，避免魔法值散落 */
const site = {
	im: "https://imdesktop.douyin.com",
	web: "https://www.douyin.com",
	edge: "https://www-hj.douyin.com",
	api: "https://imapi.douyin.com",
	apiAlt: "https://imapi3-normal.zijieapi.com",
	vod: "https://vod.bytedanceapi.com/",
	cdn: "https://p3-sign.douyinpic.com/obj/im-resource/",
	referer: "https://www.douyin.com/",
	peer: "https://vc-gate-edge.ndcpp.com/sdk/get_peer"
};
const api = {
	activeUpdate: "/aweme/v1/web/im/user/active/update/?action=heartbeat&new_user_login=0",
	activeStatus: "/aweme/v1/web/im/user/active/status/",
	activeConfig: "/aweme/v1/web/im/user/active/config/get",
	readSwitch: "/aweme/v1/web/im_communication/msg_read_switch/",
	noticeCount: "/aweme/v1/web/notice/count/",
	notice: "/aweme/v1/web/notice/",
	desktopSetting: "/aweme/v1/im/desktop/setting/get",
	userSettings: "/aweme/v1/web/user/settings/",
	compliance: "/aweme/v1/web/compliance/settings/",
	familiar: "/aweme/v1/web/familiar/list/",
	bubble: "/aweme/v1/web/im/bubble/detail_list/",
	spotlight: "/aweme/v1/web/im/spotlight/relation",
	follow: "/aweme/v1/web/commit/follow/user/",
	shareVerify: "/aweme/v1/web/im_group_api/share/verification/",
	userInfo: "/aweme/v1/web/im/user/info/",
	profileScene: "/aweme/v1/web/user/profile/scene/",
	profileOther: "/aweme/v1/web/user/profile/other/",
	profileSelf: "/aweme/v1/web/user/profile/self/",
	playInfo: "/maya/story/batch_play_info/v1/",
	awemeDetail: "/aweme/v1/web/multi/aweme/detail/",
	emojiList: "/aweme/v1/web/emoji/list/",
	resourceList: "/aweme/v1/web/im/resource/list/aggregation/",
	stickerCollect: "/aweme/v1/web/im/resource/sticker/collect/",
	trending: "/aweme/v1/web/im/resources/emoticon/trending",
	strategy: "/aweme/v1/web/im/strategy/config",
	privacy: "/aweme/v1/web/privacy/batch_build_image/",
	uploadConfig: "/aweme/v1/web/im/upload/config/v2",
	danmaku: "/aweme/v1/web/danmaku/get_v2/",
	playProgress: "/aweme/v1/web/play/progress/",
	seriesRecord: "/aweme/v1/web/series/watch/record/",
	mixRecord: "/aweme/v1/web/mix/watch/record/",
	history: "/aweme/v1/web/history/write/",
	safety: "/aweme/v2/video/safety/check/",
	upload: "/upload/v1/",
	accountInfo: "/passport/account/info/v2/",
	tokenBeat: "/passport/token/beat/web/"
};
const time$1 = {
	emoji: 3e5,
	trending: 3e5
};
const vod = {
	region: "cn-north-1",
	service: "vod",
	part: 5242880
};
/** 接口携带的固定版本号与 aid */
const ver = {
	beat: "1.2.13",
	webAid: 6383
};
/** 验证 / WS 请求头复用值 */
const ws$1 = {
	sdk: "2",
	passport: "601504",
	dp: "1128",
	region: "cn",
	regionSrc: "uid",
	kmsv: "1",
	qos: "1",
	ack: "1"
};
const frontierHost = "wss://frontier-aweme-lf-ipainner.amemv.com";
/** 协议固定值：SDK 身份、Frontier 地址、体量限制 */
const cmd = {
	bodyless: [50005],
	host: frontierHost,
	frontier: `${frontierHost}/ws/v2`,
	appKey: "e1bd35ec9db7b8d846de66ed140b1ad9",
	salt: "f8a69f1719916z",
	ua: "okhttp/3.12.1 com.ss.android.ugc.aweme/280400",
	sdk: "5.0.3.0-rc.11-SNAPSHOT",
	version: "0.7.2-fix.1",
	build: "2f4951d:fix/douyin-creator-fix",
	depth: 8
};
//#endregion
//#region src/contact/self.ts
/** 自身资料：自动获取 uid 与昵称/头像，供登录收尾与 Bot 构造 */
/** GET /aweme/v1/web/user/profile/self/ — 桌面 IM 自我资料（对齐 douyin-im getSelfProfile） */
async function self(http) {
	const params = new URLSearchParams({
		aid: im.aid,
		version_name: im.version,
		version_code: im.version,
		device_platform: mac.platform,
		screen_width: mac.width,
		screen_height: mac.height,
		browser_language: "zh-CN",
		browser_platform: mac.browserPlatform,
		browser_name: mac.browserName,
		browser_version: http.ua.replace(/^Mozilla\//, ""),
		browser_online: "true",
		cookie_enabled: "true",
		device_id: http.deviceId,
		did: http.deviceId,
		iid: http.installId,
		awemeim_guid: http.guid,
		channel: mac.channel
	});
	const user = (await http.json(`${im.origin}${api.profileSelf}?${params}`)).data["user"] ?? {};
	const nickname = typeof user["nickname"] === "string" ? user["nickname"] : void 0;
	const uid = user["uid"] ?? user["user_id_str"] ?? user["user_id"];
	const thumb = user["avatar_thumb"];
	const avatar = Array.isArray(thumb?.url_list) ? thumb.url_list.find((url) => typeof url === "string" && url !== "") : void 0;
	return {
		...uid != null ? { uid: String(uid) } : {},
		...nickname ? { nickname } : {},
		...avatar ? { avatar } : {}
	};
}
//#endregion
//#region src/session/pb.ts
/** 只用到 fromString：把 Long 收窄成最小接口，避免整个 Long 类型泄漏到业务层 */
const LONG = protobuf.util.Long;
//#endregion
//#region src/live/proto.ts
/**
* 抖音 IM 协议 schema（等价迁移自 douyin-im src/services/im/proto/im.proto）。
* tsdown 打包单文件时独立 .proto 不会被携带，因此内联为字符串常量，
* 用 protobuf.parse（keepCase=false，与 protobuf.load 默认行为一致）解析。
*/
const IM_PROTO_SOURCE = `
syntax = "proto3";
package im;

message RequestEnvelope {
  int32 cmd = 1;
  int64 sequence_id = 2;
  string sdk_version = 3;
  string token = 4;
  int32 refer = 5;
  int32 inbox_type = 6;
  string build_number = 7;
  RequestPayload body = 8;
  string device_id = 9;
  string channel = 10;
  string device_platform = 11;
  string device_type = 12;
  string os_version = 13;
  string version_code = 14;
  map<string, string> headers = 15;
  int32 config_id = 16;
  TokenInfo token_info = 17;
  int32 auth_type = 18;
  string biz = 21;
  string access = 22;
  string ts_sign = 23;
  string sdk_cert = 24;
  string reuqest_sign = 25;
}

message TokenInfo {
  int32 mark_id = 1;
  int32 type = 2;
  int32 app_id = 3;
  int64 user_id = 4;
  int64 timestamp = 5;
}

message RequestPayload {
  SendMessageRequest send_message = 100;
  InboxRequest inbox = 203;
  ConversationMessagesRequest conversation_messages = 301;
  SendUserActionRequest send_user_action = 410;
  SendInputStatusRequest send_input_status = 411;
  DeleteConversationRequest delete_conversation = 603;
  // Native rawMarkConversationRead uses outer cmd 2002 but keeps body oneof tag 604.
  MarkConversationReadRequest mark_conversation_read = 604;
  ConversationParticipantsListRequest conversation_participants = 605;
  GetConversationInfoV2Request get_conversation_info_v2 = 608;
  CreateConversationV2Request create_conversation_v2 = 609;
  GetConversationInfoListV2Request get_conversation_info_list_v2 = 610;
  DissolveConversationRequest dissolve_conversation = 614;
  ConversationAddParticipantsRequest conversation_add_participants = 650;
  ConversationRemoveParticipantsRequest conversation_remove_participants = 651;
  ConversationLeaveRequest leave_conversation = 652;
  ConversationSetRoleRequest conversation_set_role = 653;
  DeleteMessageRequest delete_message = 701;
  RecallMessageRequest recall_message = 702;
  ModifyMessagePropertyRequest modify_message_property = 705;
  SetConversationCoreInfoRequest set_conversation_core_info = 902;
  GetConversationSettingInfoRequest get_conversation_setting_info = 920;
  SetConversationSettingInfoRequest set_conversation_setting_info = 921;
  ConversationListRequest conversation_list = 2006;
  AckConversationApplyRequest ack_conversation_apply = 2025;
  GetConversationAuditListRequest get_conversation_audit_list = 2027;
  GetFriendReceiveApplyListRequest get_friend_receive_apply_list = 2048;
  ReplyFriendApplyRequest reply_friend_apply = 2049;
  GetRecentStrangerMessageReqBody get_recent_stranger_message = 12047;
  CreateVoipRequestBody create_voip = 2011;
  CallVoipRequestBody call_voip = 2012;
  // 以下对齐 native 客户端一并支持的查询/回执类接口：
  // stranger get_conversation_list 外层 cmd=1001、body oneof 独立占 tag=1000
  StrangerConversationListRequest stranger_conversation_list = 1000;
  GetReadIndexRequest get_read_index = 2000;
  GetMinIndexRequest get_min_index = 2001;
  ClientAckRequest client_ack = 2010;
  GetUserMessageRequest get_user_message = 12048;
  GetConversationParticipantsReadIndexRequest get_conversation_participants_read_index = 2038;
  MgetConversationParticipantsRequest mget_conversation_participants_body = 654;
  PullMarkMessageRequest pull_mark_message_body = 2037;
  GetCmdMessageRequest get_cmd_message_body = 2040;
  GetMessageRangeRequest get_message_info_by_index_v2_range_body = 2041;
  MessageByInitRequest message_by_init = 2043;
  ThreadMessageByInitRequest thread_message_by_init = 2204;
  GetMessageByIdRequest get_message_by_id_body = 211;
  GetMessagesByIdListRequest get_messages_by_server_id_list_body = 212;
  GetConversationMessagesByTimeRequest get_conversation_messages_by_time_body = 310;
  MarkMessageRequest mark_message_body = 2036;
  ModifyMessageExtRequest modify_message_ext_body = 2021;
  GetCmdMessageRangeRequest get_cmd_message_range_body = 12040;
  GetSpecifiedMessageListRequest get_conversation_specified_message_list_body = 12050;
  GetConversationInfoListByFavoriteRequest get_conversation_info_list_by_favorite_v2_body = 611;
  GetConversationInfoListByTopRequest get_conversation_info_list_by_top_v2_body = 612;
  BatchMarkConversationReadRequest batch_mark_read_body = 613;
  BatchDeleteConversationRequest batch_delete_conversation_body = 619;
  ClearConversationMessageRequest clear_conversation_message_v2_body = 620;
  GetConversationMemberListRequest get_conversation_member_list_body = 12060;
  BatchGetConversationMemberListRequest batch_get_conversation_member_list_body = 12061;
  GetRecentCmdConvRequest get_recent_cmd_conv = 12062;
  GetRecentStrangerConvRequest get_recent_stranger_conv = 12063;
  UpdateThreadSubscribeStatusRequest update_thread_subscribe_status = 2205;
}

message GetConversationInfoV2Request {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message GetConversationInfoListV2Request {
  repeated GetConversationInfoV2Request conversation_info_list = 1;
}

message GetConversationInfoV2Response {
  ConversationV2 conversation_info = 1;
}

message GetConversationInfoListV2Response {
  repeated ConversationV2 conversation_info_list = 1;
}

message SendUserActionRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int32 action_type = 4;
  map<string, string> extra = 5;
}

message SendInputStatusRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int32 status = 4;
  map<string, string> extra = 5;
}

message CreateVoipRequestBody {
  string idempotent_id = 1;
  // VoipType：1=ALL 2=VIDEOONLY 3=AUDIOONLY
  int32 v_type = 2;
  int64 con_short_id = 3;
  int64 srv_msg_id = 4;
  string ref_channel_id = 5;
  // VoipMode：0=DOUBLE 1=MULTIPLAYER
  int32 voip_mode = 6;
}

message CreateVoipResponseBody {
  VoipInfo info = 1;
  // VoipStatusCode：0=SUCCESS 4=PARAMS_ERROR 18=STATUS_ERROR ...
  int32 status_code = 2;
  int32 voip_mode = 3;
}

message CallVoipRequestBody {
  repeated int64 callee_ids = 1;
  string channel_id = 2;
  int32 v_type = 3;
  map<string, string> ext = 4;
  repeated int64 ref_channel_users = 5;
  string con_id = 6;
}

message CallVoipResponseBody {
  VoipInfo info = 1;
  repeated int64 callee_ids = 2;
  int32 status = 3;
  string extra_info = 4;
  int64 check_code = 5;
  string check_message = 6;
  string ref_channel_id = 7;
  int32 voip_mode = 8;
}

message VoipInfo {
  int64 user_id = 1;
  string device_id = 2;
  string channel_id = 3;
  string token = 4;
  // VoipStatus：1=CALLING 2=RINGING 3=ACCEPTED 4=ONTHECALL 101+=结束态
  int32 status = 5;
  int64 caller_id = 6;
  int64 created_time_ms = 7;
  int64 updated_time_ms = 8;
  int64 con_short_id = 9;
  int32 v_type = 10;
  int64 srv_msg_id = 11;
}

message DissolveConversationRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message ModifyPropertyContent {
  int32 operation = 1;
  string key = 2;
  string value = 3;
  string idempotent_id = 4;
}

message ModifyPropertyBody {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 server_message_id = 4;
  string client_message_id = 5;
  repeated ModifyPropertyContent modify_property_content = 6;
}

message ModifyMessagePropertyRequest {
  repeated ModifyPropertyBody property_list = 1;
  string ticket = 2;
}

message GetFriendReceiveApplyListRequest {
  int64 cursor = 1;
  int64 limit = 2;
  bool get_total_count = 3;
  int32 status = 4;
}

message ReplyFriendApplyRequest {
  repeated int64 user_id = 1;
  int32 attitude = 2;
  map<string, string> ext = 3;
}

message CreateConversationV2Request {
  int32 conversation_type = 1;
  repeated int64 participants = 2;
  bool persistent = 3;
  string idempotent_id = 4;
  string name = 6;
  string avatar_url = 7;
  string description = 8;
  map<string, string> biz_ext = 11;
  map<string, string> ext = 13;
}

message ConversationAddress {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message DeleteConversationRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_message_index = 4;
  int64 last_message_index_v2 = 5;
  int32 badge_count = 6;
}

message MarkConversationReadRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 read_message_index = 4;
  int64 conv_unread_count = 5;
  int64 total_unread_count = 6;
  int64 read_message_index_v2 = 7;
  int32 read_badge_count = 8;
  string ticket = 9;
  int64 server_message_id = 10;
}

message ConversationAddParticipantsRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  repeated int64 participants = 4;
  map<string, string> biz_ext = 5;
}

message ConversationParticipantsListRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 cursor = 4;
  int32 limit = 5;
}

message ConversationSetRoleRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  map<int64, int32> roles = 4;
}

message ConversationRemoveParticipantsRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  repeated int64 participants = 4;
  map<string, string> biz_ext = 5;
}

message ConversationLeaveRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
}

message DeleteMessageRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 message_id = 4;
}

message SetConversationCoreInfoRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  string name = 4;
  string desc = 5;
  string icon = 6;
  string notice = 7;
  bool is_name_set = 8;
  bool is_desc_set = 9;
  bool is_icon_set = 10;
  bool is_notice_set = 11;
  map<string, string> ext = 12;
}

message SetConversationSettingInfoRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  bool set_stick_on_top = 4;
  bool set_mute = 5;
  bool set_favorite = 6;
}

message GetConversationSettingInfoRequest {
  int64 conversation_short_id = 2;
}

message ConversationListRequest {
  int32 list_type = 1;
  int64 cursor = 2;
  int32 sort_type = 3;
  int32 limit = 4;
}

message AckConversationApplyRequest {
  int64 apply_id = 1;
  int32 apply_status = 2;
  map<string, string> biz_ext = 3;
}

message GetConversationAuditListRequest {
  int64 cursor = 1;
  int32 limit = 2;
  int64 conv_short_id = 3;
  bool no_clear_unread = 4;
}

message RecallMessageRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 server_message_id = 4;
}

message InboxRequest {
  int64 cursor = 1;
  int32 new_user = 2;
  int32 init_sub_type = 3;
  int32 conv_limit = 4;
  int32 msg_limit = 5;
}

message SendMessageRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  string content = 4;
  map<string, string> ext = 5;
  int32 message_type = 6;
  string ticket = 7;
  string client_message_id = 8;
  repeated int64 mentioned_users = 9;
  // field 10：盖楼归属候选落点（type=50 三元组唯一空缺）；
  // 实测差分：int64(wire0) 与缺省同为 status=4（wire0 被忽略）；string(wire2) 首段纯数字为 -1（值被拒）→
  // 真实类型是 string，值应为 thread_id 全串（服务器唯一见过的 thread 标识：落地帧 f500.f2 / emoticon conv_id）
  string thread_id = 10;
  ReferencedMessageInfo ref_msg_info = 11;
}

message ReferencedMessageInfo {
  int64 referenced_message_id = 1;
  string hint = 2;
  int64 root_message_id = 3;
  int64 root_message_conv_index = 4;
}

message ConversationMessagesRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int32 direction = 4;
  int64 anchor_index = 5;
  int32 limit = 6;
}

message ResponseEnvelope {
  int32 cmd = 1;
  int64 sequence_id = 2;
  int32 status_code = 3;
  string error_desc = 4;
  int32 inbox_type = 5;
  ResponsePayload body = 6;
  string log_id = 7;
  map<string, string> headers = 8;
  int64 start_time_stamp = 9;
  int64 request_arrived_time = 10;
  int64 server_execution_end_time = 11;
  int64 user_id = 13;
}

message Frame {
  uint64 seqid = 1;
  uint64 logid = 2;
  int32 service = 3;
  int32 method = 4;
  repeated FrameHeaderEntry headers = 5;
  string payload_encoding = 6;
  string payload_type = 7;
  bytes payload = 8;
}

message FrameHeaderEntry {
  string key = 1;
  string value = 2;
}

message ResponsePayload {
  SendMessageResponse send_message = 100;
  InboxResponse inbox = 203;
  ConversationMessagesResponse conversation_messages = 301;
  NewMessageNotify has_new_message_notify = 500;
  MarkConversationReadNotify has_mark_read_notify = 501;
  ConversationInfoUpdatedNotify has_conversation_info_updated_notify = 502;
  NewP2PMessageNotify has_new_p2p_message_notify = 504;
  NewFriendMessageNotify new_friend_message_notify = 507;
  ConversationParticipantsListResponse conversation_participants = 605;
  GetConversationInfoV2Response get_conversation_info_v2 = 608;
  CreateConversationV2Response create_conversation_v2 = 609;
  GetConversationInfoListV2Response get_conversation_info_list_v2 = 610;
  EmptyActionResponse dissolve_conversation = 614;
  ConversationAddParticipantsResponse conversation_add_participants = 650;
  ConversationRemoveParticipantsResponse conversation_remove_participants = 651;
  ConversationSetRoleResponse conversation_set_role = 653;
  RecallMessageResponse recall_message = 702;
  ModifyMessagePropertyResponse modify_message_property = 705;
  SetConversationCoreInfoResponse set_conversation_core_info = 902;
  GetConversationSettingInfoResponse get_conversation_setting_info = 920;
  SetConversationSettingInfoResponse set_conversation_setting_info = 921;
  ConversationListResponse conversation_list = 2006;
  AckConversationApplyResponse ack_conversation_apply = 2025;
  GetConversationAuditListResponse get_conversation_audit_list = 2027;
  GetFriendReceiveApplyListResponse get_friend_receive_apply_list = 2048;
  EmptyActionResponse reply_friend_apply = 2049;
  GetRecentStrangerMessageRespBody get_recent_stranger_message = 12047;
  // stranger_list 实测服务端限流返回空 body，留空响应承接
  EmptyActionResponse stranger_conversation_list = 1000;
  GetReadIndexResponse get_read_index = 2000;
  GetMinIndexResponse get_min_index = 2001;
  GetUserMessageResponse get_user_message = 12048;
  // delete/leave/readIndex 服务端返回空 body，留空响应承接
  EmptyActionResponse delete_conversation = 603;
  EmptyActionResponse leave_conversation = 652;
  EmptyActionResponse get_conversation_participants_read_index = 2038;
  MgetConversationParticipantsResponse mget_conversation_participants_body = 654;
  PullMarkMessageResponse pull_mark_message_body = 2037;
  GetCmdMessageResponse get_cmd_message_body = 2040;
  GetMessageRangeResponse get_message_info_by_index_v2_range_body = 2041;
  MessageByInitResponse message_by_init = 2043;
  MessageByInitResponse thread_message_by_init = 2204;
  GetMessageByIdResponse get_message_by_id_body = 211;
  GetMessagesByIdListResponse get_messages_by_id_list_body = 212;
  GetConversationMessagesByTimeResponse get_conversation_messages_by_time_body = 310;
  MarkMessageResponse mark_message_body = 2036;
  ModifyMessageExtResponse modify_message_ext_body = 2021;
  GetCmdMessageRangeResponse get_cmd_message_range_body = 12040;
  GetSpecifiedMessageListResponse conversation_specified_message_list_body = 12050;
  ConversationListV2Response get_conversation_info_list_by_favorite_v2_body = 611;
  ConversationListV2Response get_conversation_info_list_by_top_v2_body = 612;
  EmptyActionResponse batch_mark_read_body = 613;
  BatchDeleteConversationResponse batch_delete_conversation_body = 619;
  ClearConversationMessageV2Response clear_conversation_message_v2_body = 620;
  GetConversationMemberListResponse get_conversation_member_list_body = 12060;
  BatchGetConversationMemberListResponse batch_get_conversation_member_list_body = 12061;
  GetRecentCmdConvResponse get_recent_cmd_conv = 12062;
  GetRecentStrangerConvResponse get_recent_stranger_conv = 12063;
  UpdateThreadSubscribeStatusResponse update_thread_subscribe_status = 2205;
}

message GetRecentStrangerMessageReqBody {
  int64 latest_stranger_version = 1;
  int64 earliest_stranger_version = 2;
  string source = 3;
  int32 new_user = 4;
  map<string, string> ext = 5;
  string biz_info = 6;
}

message ConversationRecentMessage {
  int64 conversation_short_id = 1;
  repeated ConversationMessage messages = 2;
  int64 version = 3;
  int64 badge_count = 4;
  string conversation_id = 5;
  repeated ConversationMessage ext_messages = 6;
  int32 conversation_type = 11;
  int64 parent_conv_short_id = 12;
  int64 root_message_id = 14;
}

message GetRecentStrangerMessageRespBody {
  int64 next_stranger_version = 1;
  repeated ConversationRecentMessage messages = 2;
  bool has_more = 3;
}

message EmptyActionResponse {}

message ModifyMessagePropertyResponse {
  int32 status = 1;
  int64 version = 2;
}

message Profile {
  string nick_name = 1;
  string protrait = 2;
  string basic_ext_info = 3;
  string detail_ext_info = 4;
  int64 uid = 5;
}

message ApplyUserInfo {
  int64 user_id = 1;
  int64 apply_time_second = 2;
  map<string, string> ext = 3;
  int32 status = 4;
  Profile profile = 5;
}

message GetFriendReceiveApplyListResponse {
  int64 next_cursor = 1;
  bool has_more = 2;
  repeated ApplyUserInfo user_list = 3;
  int64 total_count = 4;
}

message NewFriendMessageNotify {
  int32 message_type = 1;
  int64 from_id = 2;
  int64 to_id = 3;
  string content = 4;
  map<string, string> ext = 5;
}

message CreateConversationV2Response {
  int64 check_code = 2;
  ConversationV2 conversation = 3;
  string extra_info = 4;
  int32 status = 5;
}

message ConversationApplyInfo {
  int64 user_id = 1;
  int64 conv_short_id = 2;
  int32 conversation_type = 3;
  int32 apply_status = 4;
  int64 apply_id = 5;
  int64 create_time = 6;
  int64 modify_time = 7;
  int64 modify_user = 8;
  string sec_uid = 9;
  int64 invite_user_id = 10;
  string sec_invite_uid = 11;
  map<string, string> ext = 12;
  string apply_reason = 13;
}

message AckConversationApplyResponse {
  ConversationApplyInfo apply_info = 1;
  int32 status = 2;
  int64 check_code = 3;
  string check_message = 4;
}

message GetConversationAuditListResponse {
  repeated ConversationApplyInfo apply_info_list = 1;
  int64 next_cursor = 2;
  bool has_more = 3;
}

message ConversationAddParticipantsResponse {
  repeated int64 success_participants = 1;
  repeated int64 failed_participants = 2;
  int32 status = 3;
  string extra_info = 4;
  int64 check_code = 5;
  string check_message = 6;
  repeated SecUidPair sec_success_participants = 7;
  repeated SecUidPair sec_failed_participants = 8;
}

message SecUidPair {
  int64 uid = 1;
  string sec_uid = 2;
}

message ConversationParticipant {
  int64 user_id = 1;
  int64 sort_order = 2;
  int32 role = 3;
  string alias = 4;
  string sec_uid = 5;
  int32 blocked = 6;
  int64 left_block_time = 7;
  map<string, string> ext = 8;
}

message ConversationParticipantsPage {
  repeated ConversationParticipant participants = 1;
  bool has_more = 2;
  int64 cursor = 3;
}

message ConversationParticipantsListResponse {
  ConversationParticipantsPage participants_page = 1;
}

message ConversationSetRoleResponse {
  repeated int64 success_participants = 1;
  repeated int64 failed_participants = 2;
  int32 status = 3;
  string extra_info = 4;
  int64 check_code = 5;
  string check_message = 6;
}

message ConversationRemoveParticipantsResponse {
  repeated int64 failed_participants = 1;
  int32 status = 2;
  string extra_info = 3;
  int64 check_code = 4;
  string check_message = 5;
}

message SetConversationCoreInfoResponse {
  int32 status = 2;
  string extra_info = 3;
  int64 check_code = 4;
  string check_message = 5;
}

message SetConversationSettingInfoResponse {
  ConversationSettingInfo conversation_setting_info = 1;
  int32 status = 2;
  int64 check_code = 3;
  string check_message = 4;
  string extra_info = 5;
}

message GetConversationSettingInfoResponse {
  ConversationSettingInfo conversation_setting_info = 1;
  int32 status = 2;
  int64 check_code = 3;
  string check_message = 4;
  string extra_info = 5;
}

message ConversationSettingInfo {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int32 mute = 6;
  int32 stick_on_top = 7;
  int32 inbox_type = 8;
  int32 favorite = 11;
}

message ConversationListResponse {
  repeated Conversation conversations = 1;
}

message RecallMessageResponse {
  int32 status = 1;
}

message NewMessageNotify {
  reserved 1;
  string conversation_id = 2;
  int32 conversation_type = 3;
  int32 notify_type = 4;
  ConversationMessage message = 5;
}

message NewP2PMessageNotify {
  reserved 1;
  string conversation_id = 2;
  int32 conversation_type = 3;
  ConversationMessage message = 4;
}

message MarkConversationReadNotify {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 read_message_index = 3;
  int64 read_message_index_v2 = 4;
}

message ConversationInfoUpdatedNotify {
  Conversation conversation = 1;
}

message InboxResponse {
  repeated ConversationMessage messages = 1;
  repeated Conversation conversations = 2;
  int64 next_cursor = 3;
  int32 inbox_unread_count = 4;
  int32 has_more = 5;
  int32 filter_type = 6;
  int32 total_count = 7;
  int64 min_cursor = 8;
  int64 max_cursor = 9;
}

message ConversationV2 {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  string ticket = 4;
  ConversationParticipantsPage first_page_participants = 6;
  int32 participants_count = 7;
  bool is_participant = 8;
  int32 inbox_type = 9;
  int32 badge_count = 10;
  ConversationCoreInfo conversation_core_info = 50;
}

message ConversationCoreInfo {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 info_version = 4;
  string name = 5;
  string desc = 6;
  string icon = 7;
  int32 inbox_type = 8;
  string notice = 9;
  map<string, string> ext = 11;
  int64 owner = 12;
  string sec_owner = 13;
  int64 creator_uid = 17;
  int64 create_time = 18;
}

message Conversation {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  string ticket = 4;
  int32 inbox_type = 5;
  ConversationMembers members = 6;
  int64 min_index = 10;
  int64 max_index = 11;
  int64 unread_count = 15;
  ConversationLastSender last_sender = 20;
  ConversationExtInfo ext_info = 50;
  ConversationUserSetting user_setting = 51;
}

message ConversationMembers {
  repeated ConversationMember members = 1;
}

message ConversationMember {
  int64 uid = 1;
  int32 role = 3;
  string sec_uid = 5;
}

message ConversationLastSender {
  int64 sender_uid = 1;
  int32 status = 3;
  string nickname = 4;
  string sec_uid = 5;
}

message ConversationExtInfo {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_active_time = 4;
  string name = 5;
  string avatar = 7;
  int64 owner_uid = 12;
  string owner_sec_uid = 13;
  int64 create_time = 18;
}

message ConversationUserSetting {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_msg_time = 10;
}

message SendMessageResponse {
  int64 server_message_id = 1;
  string extra_info = 2;
  int32 status = 3;
  string client_message_id = 4;
  int64 check_code = 5;
  string check_message = 6;
}

message ConversationMessagesResponse {
  repeated ConversationMessage messages = 1;
  int64 next_cursor = 2;
  bool has_more = 3;
}

message ConversationMessage {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 server_message_id = 3;
  int64 index_in_conversation = 4;
  int64 conversation_short_id = 5;
  int32 message_type = 6;
  int64 sender = 7;
  string content = 8;
  map<string, string> ext = 9;
  int64 create_time = 10;
  int64 version = 11;
  int32 status = 12;
  int64 order_in_conversation = 13;
  string sec_sender = 14;
  int64 index_in_conversation_v2 = 17;
}

// cmd=1001 stranger/get_conversation_list —— 陌生人会话列表，body oneof 占 tag=1000。
// HAR 实测被网关限流（statusCode=409 空 body），schema 按请求方向还原；
// 游标/来源/场景三字段语义为推测。
message StrangerConversationListRequest {
  int64 cursor = 1;
  int32 source = 2;
  int32 scene = 3;
}

// cmd=2000 conversation/get_read_index —— 按会话批量查各成员已读游标（微秒时间戳量级）
message GetReadIndexRequest {
  int64 conversation_short_id = 1;
  int32 conversation_type = 2;
  string conversation_id = 3;
}

message ReadIndexItem {
  int64 uid = 1;
  int64 read_index = 3;
  // 附加计数（如已读消息条数），语义推测
  int64 extra = 4;
}

message GetReadIndexResponse {
  repeated ReadIndexItem read_index_list = 1;
}

// cmd=2001 conversation/get_min_index —— 按会话批量查最小同步游标（与 get_read_index 同形）
message GetMinIndexRequest {
  int64 conversation_short_id = 1;
  int32 conversation_type = 2;
  string conversation_id = 3;
}

// cmd=2038 conversation/batch_get_conversation_participants_readindex —— 批量查询所有成员已读游标
message GetConversationParticipantsReadIndexRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 get_user_read_index = 4;
}

message MinIndexItem {
  int64 uid = 1;
  int64 min_index = 3;
}

message GetMinIndexResponse {
  repeated MinIndexItem min_index_list = 1;
}

// cmd=2010 client/ack —— 客户端消息回执（type=500 到达/已读确认）。
// HAR 响应仅 envelope 成功帧，无 payload body。
message ClientAckRequest {
  int64 server_message_id = 1;
  int32 message_type = 2;
  int32 status = 3;
  // 附加消息体原样透传（native 里携带会话诊断信息，结构不固定用 bytes 承接）
  bytes extra = 4;
  int64 client_message_id = 5;
  int64 conversation_short_id = 6;
  int32 count = 7;
}

// cmd=12048 message/get_user_message —— 增量拉会话/消息，同时下发 cmd 链路版本游标
message GetUserMessageRequest {
  int64 version = 1;
  int64 cmd_index = 2;
  int64 stranger_version = 3;
  int64 read_version = 4;
  string source = 5;
  int64 consult_version = 6;
  int64 notify_version = 17;
  int64 thread_version = 19;
  int64 thread_read_version = 20;
  bool need_recent_conv_read_info = 21;
  int64 cmd_message_chain_v2_index = 22;
}

message GetRecentMsgVersionRange {
  int64 left_side = 1;
  int64 right_side = 2;
}

message GetRecentMessageRespBody {
  int64 next_conversation_version = 1;
  repeated ConversationRecentMessage messages = 2;
  bool has_more = 3;
  GetRecentMsgVersionRange range = 4;
}

message GetCmdMessageChainV2RespBody {
  repeated ConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_cmd_message_chain_v2_index = 3;
}

message GetUserMessageResponse {
  GetRecentMessageRespBody messages = 1;
  GetCmdMessageResponse cmd_messages = 2;
  bool has_stranger_message = 3;
  GetCmdMessageChainV2RespBody cmd_message_chain_v2 = 19;
  int64 max_cmd_message_conv_version = 20;
}

// cmd=654 conversation/batch_get_member_list —— 按 uid 精确取成员，不必拉全量
message MgetConversationParticipantsRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  repeated int64 participants = 4;
}

message MgetConversationParticipantsResponse {
  repeated ConversationParticipant participants = 1;
}

// cmd=2037 message/pull_mark —— 按标记位增量拉消息
message PullMarkMessageRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 cursor = 4;
  int64 limit = 5;
  bool asc = 6;
  int32 action_type = 7;
  int64 tag = 8;
  bool clear_unread_count = 9;
}

// 服务端字段顺序按参考 proto；消息体复用 ConversationMessage，隐藏字段解码时忽略
message PullMarkMessageResponse {
  repeated ConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_cursor = 3;
}

// cmd=2040 conversation/get_recent_cmd_conv —— 拉取最近的控制类消息
message GetCmdMessageRequest {
  int64 cmd_index = 1;
  string source = 2;
  int32 new_user = 3;
}

message GetCmdMessageResponse {
  repeated ConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_cmd_index = 3;
  int64 next_user_message_cursor = 4;
  int64 readconv_version = 5;
}

// cmd=2041 message/get_message_by_index_v2_range —— 按会话内 v2 索引区间取消息
message GetMessageRangeRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 min_index_in_conversation_v2 = 4;
  int64 max_index_in_conversation_v2 = 5;
  int32 direction = 6;
}

message MessageInfo {
  int32 status = 1;
  ConversationMessage body = 2;
}

message GetMessageRangeResponse {
  repeated MessageInfo infos = 1;
  int64 next_index_in_conversation_v2 = 2;
  bool has_more = 3;
}

// cmd=2043 message/get_message_by_init —— 冷启动拉首屏消息
message MessageByInitRequest {
  int64 version = 1;
  int32 page = 2;
}

// 包装层只保留会话标识，其余字段解码时忽略
message InitConversation {
  string conversation_id = 1;
  int32 conversation_type = 2;
}

message InitConversationMessage {
  InitConversation conversations = 1;
  repeated ConversationMessage messages = 2;
  InitThreadBubble thread_bubble_message = 3;
}

// 盖楼消息：消息体与普通消息同形，只多一个方向
message InitThreadBubble {
  repeated ConversationMessage bubble_messages = 3;
  int32 message_direction = 4;
}

message MessageByInitResponse {
  repeated InitConversationMessage messages = 1;
  bool has_more = 2;
  int64 next_init_version = 3;
  int64 version = 4;
  int64 user_cursor = 5;
  int64 cmd_index = 6;
  int64 readconv_version = 7;
  int64 cmd_message_chain_v2_index = 8;
  int64 cmd_message_conv_version = 9;
}

// cmd=2204 message/get_thread_message_by_init —— 盖楼消息冷启动
message ThreadMessageByInitRequest {
  int64 thread_version = 1;
  int32 thread_limit = 2;
  int32 msg_limit = 3;
}

// cmd=211 message/get_message_by_server_id —— 按服务端消息 id 取单条
message GetMessageByIdRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 server_message_id = 4;
  bool only_status = 5;
}

message GetMessageByIdResponse {
  MessageInfo msg_info = 1;
}

// cmd=212 message/get_messages_by_server_id_list —— 批量取消息
message GetMessagesByIdListRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  repeated int64 server_message_id_list = 4;
}

message GetMessagesByIdListResponse {
  repeated MessageInfo msg_info_list = 1;
}

// cmd=310 message/get_from_conversation_by_time —— 按时间正序翻页
message GetConversationMessagesByTimeRequest {
  int64 conv_short_id = 1;
  int64 earliest_timestamp = 2;
  int64 cursor = 3;
  int64 limit = 4;
}

message GetConversationMessagesByTimeResponse {
  bool has_more = 1;
  int64 next_cursor = 2;
  repeated MessageInfo message_list = 3;
}

// cmd=2036 message/mark —— 消息标记/取消标记
message MarkMessageRequest {
  string conversation_id = 1;
  int32 conversation_type = 2;
  int64 conversation_short_id = 3;
  int64 server_message_id = 4;
  int32 do_action = 5;
  int32 action_type = 6;
  int64 sort_time = 7;
  int64 tag = 8;
}

message MarkMessageResponse {
  int64 server_message_id = 1;
  int64 check_code = 2;
  string check_message = 3;
  int32 status = 4;
}

// cmd=2021 message/modify_ext —— 修改消息扩展与内容
message ModifyMessageExtRequest {
  int64 conversation_short_id = 1;
  int64 message_id = 2;
  string ticket = 3;
  map<string, string> ext = 4;
  bool is_edited = 5;
  string content = 6;
  int32 conversation_type = 7;
  int32 message_type = 8;
  string conversation_id = 9;
}

message ModifyMessageExtResponse {
  map<string, string> ext = 1;
  int64 version = 2;
}

// cmd=12040 message/get_cmd_message_range —— 控制类消息区间
message GetCmdMessageRangeRequest {
  int64 cmd_index_v2 = 1;
  int64 size = 2;
  int32 direction = 3;
  int64 cmd_message_chain_v2_index = 4;
}

message GetCmdMessageRangeResponse {
  int64 cmd_index_v2 = 1;
  int64 size = 2;
  int32 direction = 3;
  repeated ConversationMessage messages = 4;
  int64 next_cmd_index_v2 = 5;
  int64 cmd_message_chain_v2_index = 6;
  int64 next_cmd_message_chain_v2_index = 7;
}

// cmd=12050 conversation/specified_message_list —— 指定类型消息列表
message GetSpecifiedMessageListRequest {
  int32 message_list_type = 1;
  int64 conversation_short_id = 2;
  int64 offset = 3;
  int64 count = 4;
}

message GetSpecifiedMessageListResponse {
  repeated ConversationMessage message_list = 1;
  int64 next_offset = 2;
  bool has_more = 3;
}

// cmd=611/612 conversation/get_by_favorite|get_by_top —— 收藏/置顶会话
message GetConversationInfoListByFavoriteRequest {
  int64 cursor = 1;
  int64 limit = 2;
}

message GetConversationInfoListByTopRequest {
  int64 cursor = 1;
  int64 limit = 2;
  int32 conversation_type = 3;
}

message ConversationListV2Response {
  repeated ConversationV2 conversation_info_list = 1;
  bool has_more = 2;
  int64 next_cursor = 3;
}

// cmd=613 conversation/batch_mark_read —— 批量已读
message BatchMarkConversationReadRequest {
  repeated MarkConversationReadRequest mark_read_requests = 1;
}

// cmd=619 conversation/batch_delete —— 批量删除会话
message BatchDeleteConversationRequest {
  repeated DeleteConversationRequest mark_delete_requests = 1;
}

message BatchDeleteConversationResponse {
  repeated int64 failed_conversation_short_ids = 1;
}

// cmd=620 conversation/clear_message —— 清空会话消息
message ClearConversationMessageRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 last_message_index = 4;
  int64 last_message_index_v2 = 5;
  int64 last_msg_badge_count = 6;
  int64 last_message_time = 8;
  int64 total_thread_important_badge_count = 9;
}

message ClearConversationMessageV2Response {
  bool show_empty_conv = 1;
}

// cmd=12060/12061 conversation/get_member_list|batch_get_member_list —— 成员列表
message GetConversationMemberListRequest {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int32 sync_scene = 4;
  int64 local_member_version = 5;
  int64 cursor = 6;
  int64 limit = 7;
}

message ConversationMemberList {
  string conversation_id = 1;
  int64 conversation_short_id = 2;
  int32 conversation_type = 3;
  int64 member_version = 4;
  int64 participants_count = 5;
  ConversationParticipantsPage full_participants_page = 6;
  int64 check_code = 100;
  string check_msg = 101;
}

message GetConversationMemberListResponse {
  ConversationMemberList member_list = 1;
}

message BatchGetConversationMemberListRequest {
  repeated GetConversationMemberListRequest batch_member_list = 1;
}

message BatchGetConversationMemberListResponse {
  repeated ConversationMemberList batch_member_list = 1;
}

// cmd=12062 conversation/get_recent_cmd_conv —— 最近控制类消息会话
message GetRecentCmdConvRequest {
  int64 cmd_message_conv_version = 1;
  bool reverse = 2;
  string source = 3;
}

message GetRecentCmdConvResponse {
  repeated ConversationV2 conversation_info = 1;
  bool has_more = 2;
  int64 next_cmd_message_conv_version = 3;
}

// cmd=12063 conversation/get_recent_stranger_conv —— 最近陌生人会话
message GetRecentStrangerConvRequest {
  int64 max_version = 1;
  int64 min_version = 2;
  bool reverse = 3;
  string source = 4;
}

message GetRecentStrangerConvResponse {
  repeated ConversationV2 conversation_info = 1;
  bool has_more = 2;
  int64 next_version = 3;
}

// cmd=2205 conversation/update_thread_subscribe_status —— 盖楼订阅状态
message UpdateThreadSubscribeStatusRequest {
  string thread_id = 1;
  int64 thread_short_id = 2;
  int32 status = 3;
}

message UpdateThreadSubscribeStatusResponse {
  int32 status = 1;
}
`;
let root$1;
/** 解析内联 proto（keepCase=false，与参考项目 protobuf.load 行为一致），进程内缓存 */
function loadRoot() {
	root$1 ??= protobuf.parse(IM_PROTO_SOURCE, { keepCase: false }).root;
	return root$1;
}
//#endregion
//#region src/live/codec.ts
const SDK_VERSION$1 = cmd.version;
const BUILD_NUMBER = cmd.build;
let sequenceCounter = 0;
function encodeRequest(opts) {
	const RequestEnvelope = loadRoot().lookupType("im.RequestEnvelope");
	sequenceCounter += 1;
	const envelope = {
		cmd: opts.cmd,
		sequenceId: opts.sequenceId ?? sequenceCounter,
		sdkVersion: opts.sdkVersion ?? SDK_VERSION$1,
		token: opts.token,
		refer: opts.refer ?? 3,
		inboxType: opts.inboxType ?? 1,
		buildNumber: opts.buildNumber ?? BUILD_NUMBER,
		deviceId: opts.deviceId ?? "",
		devicePlatform: opts.devicePlatform ?? "douyin_pc",
		versionCode: opts.versionCode ?? "",
		headers: opts.headers ?? {},
		authType: opts.authType ?? 3,
		biz: opts.biz ?? "douyin_creator",
		access: opts.access ?? "im_api"
	};
	if (opts.body) envelope["body"] = opts.body;
	const errMsg = RequestEnvelope.verify(envelope);
	if (errMsg) err({ reason: errMsg });
	const message = RequestEnvelope.create(envelope);
	return RequestEnvelope.encode(message).finish();
}
function decodeResponseRaw(buffer) {
	const ResponseEnvelope = loadRoot().lookupType("im.ResponseEnvelope");
	const decoded = ResponseEnvelope.decode(buffer);
	return ResponseEnvelope.toObject(decoded, {
		longs: String,
		enums: String,
		defaults: true
	});
}
//#endregion
//#region src/session/sign/frontier.ts
/** 需 WS 帧签名的命令（100 发送、411 输入状态、609/610/611 会话） */
const WS_SIGN_CMDS = /* @__PURE__ */ new Set([
	100,
	411,
	609,
	610,
	611
]);
/**
* 417.js SecurityPlugin.frontierSign：
* 1. X-MS-STUB = MD5(serialize(request))
* 2. byted_acrawler.frontierSign({ X-MS-STUB }) → { X-Bogus }
*/
function frontierSign(payload, opts = {}) {
	const stub = createHash("md5").update(payload).digest("hex");
	const headers = [{
		key: "X-MS-STUB",
		value: stub
	}];
	try {
		const xBogus = aBogus({
			userAgent: opts.userAgent ?? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			query: stub,
			body: "",
			bdmsPreset: "1.0.1.16"
		});
		if (xBogus) headers.push({
			key: "X-Bogus",
			value: xBogus
		});
	} catch {}
	return headers;
}
//#endregion
//#region src/live/profile.ts
/** 桌面 IM 客户端 UA（媒体上传与 Cookie 通道共用，macOS 口径） */
const PC_UA = mac.ua;
/** 桌面身份元信息：三处 query/header 共用，避免版本号互不一致触发风控 */
const deskMeta = {
	appId: 339757,
	appName: "aweme_im_desktop",
	version: im.version
};
/** 安卓端常量（WS 通道 cmd411 envelope 用；握手常量见 link.ts） */
const android = {
	aid: "1128",
	versionCode: "280400",
	channel: "douyinweb1_64",
	deviceType: "24031PN0DC",
	osVersion: "14",
	appName: "aweme",
	buildNumber: "5030",
	biz: "douyin",
	access: "douyin_main"
};
const ANDROID_UA = cmd.ua;
const ANDROID_SDK_VERSION = cmd.sdk;
/** config/v2 与 batch_play_info 共用的桌面指纹 query（媒体上传用） */
function fingerprintParams(deviceId, guid) {
	return new URLSearchParams({
		aid: String(deskMeta.appId),
		version_name: deskMeta.version,
		version_code: deskMeta.version,
		device_platform: mac.platform,
		os_version: mac.release,
		screen_width: mac.width,
		screen_height: mac.height,
		browser_language: "zh-CN",
		browser_platform: mac.browserPlatform,
		browser_name: mac.browserName,
		browser_version: PC_UA.replace(/^Mozilla\//, ""),
		browser_online: "true",
		cookie_enabled: "true",
		device_id: deviceId,
		did: deviceId,
		iid: "0",
		awemeim_guid: guid,
		channel: mac.channel
	});
}
/** 官方桌面客户端 queryMap（设备身份载体；native ImOption.headersMap 为空） */
function imQuery(deviceId) {
	return {
		aid: String(deskMeta.appId),
		app_name: deskMeta.appName,
		did: deviceId,
		device_id: deviceId,
		iid: "0",
		channel: mac.channel,
		os_version: mac.release,
		version_code: deskMeta.version,
		version_name: deskMeta.version,
		device_platform: "mac",
		device_type: process.arch,
		device_brand: ""
	};
}
/** 原生通道 f15 headers map（设备身份载体） */
function nativeHeaders(deviceId) {
	return {
		session_aid: String(deskMeta.appId),
		session_did: deviceId,
		app_name: "douyin_pc",
		priority_region: "cn",
		user_agent: PC_UA,
		cookie_enabled: "true",
		browser_language: "zh-CN",
		browser_platform: mac.browserPlatform,
		browser_name: mac.browserName,
		browser_version: PC_UA.replace(/^Mozilla\//, ""),
		browser_online: "true",
		screen_width: mac.width,
		screen_height: mac.height,
		referer: "",
		timezone_name: "Asia/Shanghai",
		"is-retry": "0"
	};
}
/** cmd411 内层 envelope f15 headers KV（设备身份载体） */
function androidHeaders(uid) {
	return [
		["app_name", android.appName],
		["iid", uid],
		["version_code", android.versionCode],
		["net_mcc_mnc", "46000"],
		["aid", android.aid],
		["flow-tag", "new"],
		["user-agent", ANDROID_UA]
	];
}
/** Desktop Cookie 通道（对照官方 native ImOption：设备身份走 URL query 而非 envelope headers） */
const desk = {
	url: (endpoint, deviceId) => {
		const url = new URL(endpoint, site.apiAlt);
		for (const [key, value] of Object.entries(imQuery(deviceId))) url.searchParams.set(key, value);
		return url.toString();
	},
	headers: () => ({}),
	sdkVersion: deskMeta.version,
	buildNumber: "eb11b84dd0eb26ae22321b53426d3f976b920862",
	versionCode: deskMeta.version,
	devicePlatform: "mac",
	biz: "douyin_im_pc",
	access: "cpp_sdk",
	accept: "x-protobuf",
	stub: true
};
/** 原生通道（对照 HAR：无 URL query、无 x-ss-stub；设备身份走 envelope f15 headers map） */
const native = {
	url: (endpoint, _deviceId) => `${site.api}${endpoint}`,
	headers: nativeHeaders,
	sdkVersion: "0.1.8",
	buildNumber: "0d50935:feat/pc-im-group",
	versionCode: "360000",
	devicePlatform: "douyin_pc",
	biz: "douyin_im_pc",
	access: "web_sdk",
	accept: "application/x-protobuf",
	stub: false
};
//#endregion
//#region src/live/wire.ts
/**
* 无 schema 的 protobuf wire 编解码：用于诊断与未知 IM 推送。
* 解码永不因截断抛错，只返回已完整解出的字段。
*/
const MAX_DEPTH = cmd.depth;
const textDecoder = new TextDecoder("utf-8", { fatal: true });
/** 定长 wire type 表：1=fixed64、5=fixed32（protobuf 其余定长类型不使用） */
const fixed = {
	1: {
		type: "fixed64",
		width: 8
	},
	5: {
		type: "fixed32",
		width: 4
	}
};
function decodeVarint(data, start) {
	let value = 0n;
	let shift = 0n;
	for (let pos = start; pos < data.length && shift < 70n; pos += 1, shift += 7n) {
		const byte = data[pos];
		value |= BigInt(byte & 127) << shift;
		if ((byte & 128) === 0) return {
			value,
			next: pos + 1
		};
	}
	return null;
}
function safeText(data) {
	try {
		const text = textDecoder.decode(data);
		for (const ch of text) {
			const code = ch.codePointAt(0);
			if (code < 32 && code !== 9 && code !== 10 && code !== 13) return null;
		}
		return text;
	} catch {
		return null;
	}
}
function decodeWire(data, depth = 0) {
	const fields = [];
	let pos = 0;
	while (pos < data.length) {
		const tag = decodeVarint(data, pos);
		if (!tag) break;
		pos = tag.next;
		const field = Number(tag.value >> 3n);
		const wireType = Number(tag.value & 7n);
		if (field === 0) break;
		if (wireType === 0) {
			const item = decodeVarint(data, pos);
			if (!item) break;
			pos = item.next;
			fields.push({
				field,
				type: "varint",
				value: item.value
			});
			continue;
		}
		const member = fixed[wireType];
		if (member) {
			if (pos + member.width > data.length) break;
			const value = data.slice(pos, pos + member.width);
			pos += member.width;
			fields.push({
				field,
				type: member.type,
				value
			});
			continue;
		}
		if (wireType !== 2) break;
		const lengthItem = decodeVarint(data, pos);
		if (!lengthItem || lengthItem.value > BigInt(Number.MAX_SAFE_INTEGER)) break;
		pos = lengthItem.next;
		const length = Number(lengthItem.value);
		if (pos + length > data.length) break;
		const raw = data.slice(pos, pos + length);
		pos += length;
		const text = safeText(raw);
		const trimmed = text?.trimStart() ?? "";
		const knownText = trimmed.startsWith("{") || trimmed.startsWith("[") || /^0:\d+:/.test(trimmed) || /^\d+$/.test(trimmed) || trimmed.startsWith("MS4") || /^https?:\/\//.test(trimmed) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(trimmed);
		if (text != null && knownText) {
			fields.push({
				field,
				type: "string",
				value: text
			});
			continue;
		}
		const nested = depth < MAX_DEPTH ? decodeWire(raw, depth + 1) : [];
		if (nested.length > 0) fields.push({
			field,
			type: "message",
			value: nested
		});
		else if (text != null) fields.push({
			field,
			type: "string",
			value: text
		});
		else fields.push({
			field,
			type: "bytes",
			value: raw
		});
	}
	return fields;
}
/** JSON 安全的诊断树：bigint 转十进制串，字节转 base64 */
function decodeWireTree(data) {
	const convert = (field) => {
		if (field.type === "message") return {
			f: field.field,
			t: field.type,
			v: field.value.map(convert)
		};
		if (field.type === "varint") return {
			f: field.field,
			t: field.type,
			v: field.value.toString()
		};
		if (field.type === "string") return {
			f: field.field,
			t: field.type,
			v: field.value
		};
		return {
			f: field.field,
			t: field.type,
			v: Buffer.from(field.value).toString("base64")
		};
	};
	return decodeWire(data).map(convert);
}
function encodeVarint(value) {
	let remaining = BigInt(value);
	const bytes = [];
	do {
		let byte = Number(remaining & 127n);
		remaining >>= 7n;
		if (remaining) byte |= 128;
		bytes.push(byte);
	} while (remaining);
	return Buffer.from(bytes);
}
function fieldVarint$1(field, value) {
	return Buffer.concat([encodeVarint(field << 3), encodeVarint(value)]);
}
function fieldBytes(field, value) {
	return Buffer.concat([
		encodeVarint(field << 3 | 2),
		encodeVarint(value.length),
		Buffer.from(value)
	]);
}
function fieldStringValue(field, value) {
	return fieldBytes(field, Buffer.from(value));
}
/** 嵌套 map<string,string> 键值项：field { 1: key, 2: value } */
function kv(field, key, value) {
	return fieldBytes(field, Buffer.concat([fieldStringValue(1, key), fieldStringValue(2, value)]));
}
//#endregion
//#region src/live/frame.ts
let seqCount = 0;
/** 组一条 WS cmd=411 输入状态帧：f1=411、f8=SendInputStatusRequest（三层结构与 Android Frontier WS 帧一致） */
function buildCmd411Frame(options) {
	const seq = ++seqCount;
	const ms = Date.now();
	const body = Buffer.concat([
		fieldStringValue(1, options.conversationId),
		fieldVarint$1(2, options.conversationType),
		fieldVarint$1(3, BigInt(options.conversationShortId || "0")),
		fieldVarint$1(4, options.typing ? 3 : 4)
	]);
	const parts = [
		fieldVarint$1(1, 411),
		fieldVarint$1(2, seq),
		fieldStringValue(3, ANDROID_SDK_VERSION),
		fieldVarint$1(5, 1),
		fieldVarint$1(6, 0),
		fieldStringValue(7, android.buildNumber),
		fieldBytes(8, body),
		fieldStringValue(9, options.userId),
		fieldStringValue(10, android.channel),
		fieldStringValue(11, "android"),
		fieldStringValue(12, android.deviceType),
		fieldStringValue(13, android.osVersion),
		fieldStringValue(14, android.versionCode)
	];
	for (const [key, value] of androidHeaders(options.userId)) parts.push(kv(15, key, value));
	parts.push(fieldVarint$1(18, 0), fieldStringValue(21, android.biz), fieldStringValue(22, android.access));
	const inner = Buffer.concat(parts);
	const headers = [
		["msg_type", "cmd411"],
		["seq_id", String(seq)],
		["cmd", "411"],
		["is-retry", "0"],
		["flow-tag", "new"]
	];
	if (WS_SIGN_CMDS.has(411)) for (const sign of frontierSign(inner, { userAgent: ANDROID_UA })) headers.push([sign.key, sign.value]);
	const frame = [
		fieldVarint$1(1, seq),
		fieldVarint$1(2, ms),
		fieldVarint$1(3, 5),
		fieldVarint$1(4, 1)
	];
	for (const [key, value] of headers) frame.push(kv(5, key, value));
	frame.push(fieldStringValue(6, "pb"), fieldStringValue(7, "pb"), fieldBytes(8, inner));
	return Buffer.concat(frame);
}
//#endregion
//#region src/live/link.ts
/** 指数退避：1s, 2s, 4s, ... 封顶 30s */
function reconnectDelay(attempt) {
	return Math.min(3e4, 1e3 * 2 ** Math.max(0, attempt - 1));
}
/** Cookie 串取值：解码失败时保留原串（签名/头透传比抛错更重要） */
function cookieValue(cookies, name) {
	const entry = cookies.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
	if (!entry) return void 0;
	const value = entry.slice(name.length + 1);
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}
/** WS 握手 URL：access_key 由 uid 派生，设备身份全部在 query */
function wsUrl$1(userId, now = Date.now()) {
	const accessKey = createHash("md5").update(`9${cmd.appKey}${userId}${cmd.salt}`).digest("hex");
	const params = new URLSearchParams({
		aid: "1128",
		fpid: "9",
		sdk_version: "3",
		device_id: userId,
		iid: userId,
		access_key: accessKey,
		pl: "0",
		ne: "1",
		version_code: "280400",
		version_name: "28.4.0",
		update_version_code: "28409900",
		platform: "0",
		monitor_service_id_list: "[]",
		is_background: "0",
		"ping-interval": "30",
		qos_level: "2",
		qos_sdk_version: "2",
		ttnet_ignore_offline: "1",
		ws_connect_protocol: "0",
		device_platform: "android",
		os: "android",
		app_name: "aweme",
		package: "com.ss.android.ugc.aweme",
		channel: "douyinweb1_64",
		ac: "wifi",
		language: "zh",
		device_type: "24031PN0DC",
		device_brand: "XIAOMI",
		os_api: "34",
		os_version: "14",
		ts: String(Math.floor(now / 1e3)),
		_rticket: String(Math.floor(now / 1e3) * 1e3)
	});
	return `${cmd.frontier}?${params}`;
}
/** WS 握手头：会话 Cookie 与前端固定能力标记；tlb/mfa 值来自 Cookie */
function wsHeaders$1(cookies) {
	const headers = {
		"User-Agent": ANDROID_UA,
		Origin: cmd.host,
		Cookie: cookies,
		"x-support-qos2": ws$1.qos,
		"x-support-ack": ws$1.ack,
		"sdk-version": ws$1.sdk,
		"passport-sdk-version": ws$1.passport,
		"X-SS-DP": ws$1.dp,
		"x-tt-store-region": ws$1.region,
		"x-tt-store-region-src": ws$1.regionSrc,
		"x-bd-kmsv": ws$1.kmsv
	};
	const tlbTag = cookieValue(cookies, "session_tlb_tag");
	const mfaToken = cookieValue(cookies, "passport_mfa_token");
	if (tlbTag) headers["session-tlb-tag"] = tlbTag;
	if (mfaToken) headers["x-tt-passport-mfa-token"] = mfaToken;
	return headers;
}
/** ws 的 RawData 三种形态（Buffer/数组/ArrayBuffer）统一为字节 */
function toBytes(data) {
	if (Buffer.isBuffer(data)) return data;
	return Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data);
}
//#endregion
//#region src/live/ws.ts
/** 结果已定后关闭连接：CONNECTING 只能 terminate，否则是等待 socket 挂起 */
function shut(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN) socket.close();
		else if (socket.readyState === WebSocket.CONNECTING) socket.terminate();
	} catch {}
}
/**
* Cookie 鉴权 Android Frontier WS：连接 / 15s 心跳 / 指数退避重连 / 帧分发。
* 不打印日志：正常重连等事件全部通过回调通知，由上层决定记录策略。
*/
var AndroidFrontierWs = class {
	options;
	socket;
	heartbeat;
	timer;
	task;
	attempt = 0;
	stopped = true;
	opened = false;
	constructor(options) {
		this.options = options;
	}
	get connected() {
		return this.socket?.readyState === WebSocket.OPEN;
	}
	connect() {
		if (this.connected) return Promise.resolve();
		if (this.task) return this.task;
		this.stopped = false;
		const task = this.open();
		this.task = task;
		task.then(() => this.release(task), () => this.release(task));
		return task;
	}
	close() {
		this.stopped = true;
		this.opened = false;
		this.attempt = 0;
		if (this.timer) clearTimeout(this.timer);
		delete this.timer;
		this.stopBeat();
		this.socket?.close();
		delete this.socket;
	}
	/**
	* 一次性连接发送帧并等待响应提取（Android cmd=100 直发）。
	* 返回 undefined 表示超时/连接失败/未匹配到响应。
	*/
	async sendOnce(frame, extract, ackTimeoutMs = 4e3) {
		return new Promise((resolve) => {
			const socket = this.connectSocket();
			let done = false;
			let ackTimer;
			const finish = (result) => {
				if (done) return;
				done = true;
				if (ackTimer) clearTimeout(ackTimer);
				clearTimeout(connectTimer);
				socket.off("message", onMessage);
				shut(socket);
				resolve(result);
			};
			const onMessage = (data) => {
				const result = extract(toBytes(data));
				if (result !== void 0) finish(result);
			};
			socket.once("open", () => {
				ackTimer = setTimeout(() => finish(void 0), ackTimeoutMs);
				socket.send(frame, (error) => {
					if (error) finish(void 0);
				});
			});
			socket.on("message", onMessage);
			socket.once("close", () => finish(void 0));
			socket.once("error", () => finish(void 0));
			const connectTimer = setTimeout(() => finish(void 0), 3e4);
		});
	}
	/**
	* 一次性连接发送帧即关（无回执语义，411 输入状态用）。
	* 返回 true 表示帧已成功写入连接；false 表示连接或发送失败。
	*/
	async sendFireOnce(frame) {
		return new Promise((resolve) => {
			const socket = this.connectSocket();
			let done = false;
			const finish = (ok) => {
				if (done) return;
				done = true;
				clearTimeout(guard);
				shut(socket);
				resolve(ok);
			};
			const guard = setTimeout(() => finish(false), 15e3);
			socket.once("open", () => {
				socket.send(frame, (error) => finish(!error));
			});
			socket.once("close", () => finish(false));
			socket.once("error", () => finish(false));
		});
	}
	open() {
		return new Promise((resolve, reject) => {
			const socket = this.connectSocket();
			this.socket = socket;
			let done = false;
			let isOpen = false;
			const finish = (error) => {
				if (done) return;
				done = true;
				if (error) reject(error);
				else resolve();
			};
			socket.once("error", finish);
			socket.once("unexpected-response", (_req, res) => {
				res.resume();
			});
			socket.once("open", () => {
				if (this.stopped) {
					socket.close();
					finish();
					return;
				}
				isOpen = true;
				socket.off("error", finish);
				finish();
				this.attempt = 0;
				this.opened = true;
				this.beat(socket);
				this.options.callbacks?.onOpen?.();
			});
			socket.on("message", (data) => {
				this.options.callbacks?.onMessage?.(toBytes(data));
			});
			socket.on("close", (code, reason) => {
				this.stopBeat();
				if (this.socket === socket) delete this.socket;
				const text = reason.toString();
				if (!isOpen) finish(new SdkError({
					code,
					reason: text
				}));
				this.options.callbacks?.onClose?.({
					code,
					reason: text
				});
				if (!this.stopped && this.opened) this.schedule(code, text);
			});
			socket.on("error", (error) => {
				this.options.callbacks?.onError?.(error);
			});
		});
	}
	connectSocket() {
		return new WebSocket(wsUrl$1(this.options.userId), ["pbbp2"], {
			headers: wsHeaders$1(this.options.cookies),
			handshakeTimeout: 3e4
		});
	}
	beat(socket) {
		this.heartbeat = setInterval(() => {
			if (socket.readyState === WebSocket.OPEN) socket.ping();
		}, 15e3);
	}
	schedule(code, reason) {
		if (this.stopped || this.timer) return;
		const attempt = ++this.attempt;
		const delayMs = reconnectDelay(attempt);
		const event = {
			attempt,
			delayMs
		};
		if (code != null) event.code = code;
		if (reason) event.reason = reason;
		this.options.callbacks?.onReconnecting?.(event);
		this.timer = setTimeout(() => {
			delete this.timer;
			if (this.stopped) return;
			this.open().catch(() => this.schedule());
		}, delayMs);
	}
	release(task) {
		if (this.task === task) delete this.task;
	}
	stopBeat() {
		if (this.heartbeat) clearInterval(this.heartbeat);
		delete this.heartbeat;
	}
};
//#endregion
//#region src/live/transport.ts
/** HTTP protobuf 通道：Desktop Cookie 通道（发送/收件箱查询/动作/撤回/陌生人消息） */
var ProtoTransport = class {
	http;
	log;
	constructor(http, log) {
		this.http = http;
		this.log = log;
	}
	/** Desktop Cookie 通道（设备身份在 URL query，envelope headers 为空） */
	sendCookieProto(cmd, inboxType, endpoint, body, deviceId) {
		return this.send(desk, cmd, inboxType, endpoint, body, deviceId);
	}
	/** 原生通道（imapi.douyin.com：无 URL query、无 x-ss-stub，设备身份在 envelope f15 headers map） */
	sendNativeProto(cmd, inboxType, endpoint, body, deviceId) {
		return this.send(native, cmd, inboxType, endpoint, body, deviceId);
	}
	async send(channel, cmd, inboxType, endpoint, body, deviceId) {
		const payload = Buffer.from(encodeRequest({
			token: "",
			cmd,
			inboxType,
			body,
			authType: 1,
			deviceId,
			sdkVersion: channel.sdkVersion,
			buildNumber: channel.buildNumber,
			versionCode: channel.versionCode,
			devicePlatform: channel.devicePlatform,
			biz: channel.biz,
			access: channel.access,
			headers: channel.headers(deviceId)
		}));
		const headers = {
			Accept: channel.accept,
			"Content-Type": "application/x-protobuf",
			"User-Agent": PC_UA,
			Referer: site.im
		};
		if (channel.stub) headers["x-ss-stub"] = createHash("md5").update(payload).digest("hex");
		const res = await this.http.bytes(channel.url(endpoint, deviceId), {
			method: "POST",
			headers,
			body: payload
		});
		if (!res.ok) return err(res.data);
		return this.decode(cmd, endpoint, res.data);
	}
	/** 两条通道共用的响应解码与失败诊断 */
	decode(cmd, endpoint, data) {
		const decoded = decodeResponseRaw(data);
		const statusCode = Number(decoded["statusCode"] ?? 0);
		if (statusCode !== 0) this.log.warn(`cmd=${cmd} ${endpoint} 失败: statusCode=${statusCode} errorDesc=${String(decoded["errorDesc"] ?? "")}`);
		return decoded;
	}
};
/** 一次性连接发送 cmd=411 输入状态帧（无确认回执，发完即关）；true=已发出 */
async function sendCmd411(options) {
	const frame = buildCmd411Frame(options);
	const ws = new AndroidFrontierWs({
		userId: options.userId,
		cookies: options.cookies
	});
	const ok = await ws.sendFireOnce(frame);
	ws.close();
	return ok;
}
//#endregion
//#region src/chat/map.ts
function isGroupConversationId(conversationId) {
	return /^\d+$/.test(conversationId.trim());
}
function mapProtoConversationListItem(raw) {
	const conversationId = String(raw["conversationId"] ?? "");
	const conversationType = Number(raw["conversationType"] ?? 0);
	const core = raw["conversationCoreInfo"];
	const ext = raw["extInfo"];
	const setting = raw["userSetting"] ?? raw["conversationSettingInfo"];
	const memberBox = raw["members"] ?? raw["firstPageParticipants"];
	const avatar = String(core?.["icon"] ?? ext?.["icon"] ?? core?.["avatar"] ?? ext?.["avatar"] ?? "");
	const ownerUid = String(ext?.["ownerUid"] ?? ext?.["owner"] ?? core?.["owner"] ?? "");
	const coreExt = core?.["ext"];
	const groupNumber = String(coreExt?.["a:s_group_number"] ?? ext?.["a:s_group_number"] ?? "");
	const members = (memberBox?.members ?? memberBox?.participants ?? []).map((member) => {
		const secUid = String(member["secUid"] ?? "");
		return {
			uid: String(member["uid"] ?? member["userId"] ?? ""),
			role: Number(member["role"] ?? 0),
			...secUid ? { secUid } : {}
		};
	}).filter((member) => member.uid && member.uid !== "0");
	return {
		conversationId,
		conversationShortId: String(raw["conversationShortId"] ?? ""),
		conversationType,
		isGroup: conversationType === 2 || isGroupConversationId(conversationId),
		name: String(ext?.["name"] ?? ""),
		...avatar ? { avatar } : {},
		...ownerUid && ownerUid !== "0" ? { ownerUid } : {},
		lastMessageTime: Number(setting?.["lastMsgTime"] ?? 0),
		members,
		...groupNumber ? { groupNumber } : {},
		...raw["ticket"] ? { ticket: String(raw["ticket"]) } : {}
	};
}
/** 从 conversationId 解析对端 uid（私信格式 0:1:{uid_a}:{uid_b}） */
function parsePeerFromConversationId(conversationId, myUid) {
	const parts = conversationId.split(":");
	if (parts.length >= 4 && parts[1] === "1") {
		const uidA = parts[2];
		const uidB = parts[3];
		if (uidA === myUid) return uidB;
		if (uidB === myUid) return uidA;
		return uidB;
	}
	return "";
}
/** 从 conversation 元数据构建 thread（peer 资料取 firstPageParticipants/userInfo 的 alias） */
function mapProtoConversationMeta(conv, messages, myUid) {
	const threadId = conv["conversationId"] ?? "";
	const conversationType = conv["conversationType"] ?? 1;
	const peerUid = parsePeerFromConversationId(threadId, myUid);
	const participantPage = conv["firstPageParticipants"] ?? conv["members"];
	const userInfo = conv["userInfo"];
	const peerInfo = (participantPage?.participants ?? participantPage?.members ?? []).find((member) => String(member["userId"] ?? member["uid"] ?? "") === peerUid) ?? (String(userInfo?.["userId"] ?? userInfo?.["uid"] ?? "") === peerUid ? userInfo : void 0);
	const peerSecUid = String(peerInfo?.["secUid"] ?? "");
	const peerNick = String(peerInfo?.["alias"] ?? peerInfo?.["nickname"] ?? "");
	const thread = {
		threadId,
		...conv["conversationShortId"] != null ? { conversationShortId: String(conv["conversationShortId"]) } : {},
		conversationType,
		peer: {
			uid: peerUid,
			nickname: peerNick,
			...peerSecUid ? { secUid: peerSecUid } : {}
		},
		unreadCount: Number(conv["badgeCount"] ?? conv["unreadCount"] ?? 0),
		updateTime: Number(conv["extInfo"]?.["lastActiveTime"] ?? 0),
		...conv["inboxType"] != null ? { inboxType: conv["inboxType"] } : {}
	};
	const lastMsg = messages.find((m) => m["conversationId"] === threadId);
	if (lastMsg) {
		thread.lastMessage = mapProtoMessage(lastMsg);
		if (!thread.updateTime) thread.updateTime = thread.lastMessage.createTime;
	}
	return thread;
}
/** 从单条 message 记录构建 thread（无 conversations 字段时） */
function mapProtoConversation(raw, myUid) {
	const threadId = raw["conversationId"] ?? "";
	const conversationType = raw["conversationType"] ?? 1;
	const peerUid = parsePeerFromConversationId(threadId, myUid) || (conversationType === 1 ? String(raw["sender"] ?? "") : "");
	const ext = raw["ext"];
	const thread = {
		threadId,
		...raw["conversationShortId"] != null ? { conversationShortId: String(raw["conversationShortId"]) } : {},
		conversationType,
		peer: {
			uid: peerUid,
			nickname: "",
			...raw["secSender"] && String(raw["sender"]) === peerUid ? { secUid: String(raw["secSender"]) } : {}
		},
		unreadCount: 0,
		updateTime: raw["createTime"] ?? 0,
		...ext?.["s:is_stranger"] === "true" ? { isStranger: true } : {}
	};
	if (raw["content"]) thread.lastMessage = mapProtoMessage(raw);
	return thread;
}
function dedupeThreads(threads) {
	const byId = /* @__PURE__ */ new Map();
	for (const t of threads) {
		const prev = byId.get(t.threadId);
		if (!prev || t.updateTime >= prev.updateTime) byId.set(t.threadId, t);
	}
	return [...byId.values()];
}
function mapProtoMessage(raw) {
	const senderSecUid = String(raw["secSender"] ?? "");
	const indexInConversation = String(raw["indexInConversation"] ?? "");
	const indexInConversationV2 = String(raw["indexInConversationV2"] ?? "");
	return {
		msgId: String(raw["serverMessageId"] ?? ""),
		threadId: raw["conversationId"] ?? "",
		senderUid: String(raw["sender"] ?? ""),
		...senderSecUid ? { senderSecUid } : {},
		content: raw["content"] ?? "",
		msgType: raw["messageType"] ?? 0,
		createTime: raw["createTime"] ?? 0,
		status: raw["status"] ?? 0,
		...indexInConversation ? { indexInConversation } : {},
		...indexInConversationV2 ? { indexInConversationV2 } : {}
	};
}
function parseActionCheckMessage(value) {
	if (!value.trim()) return { parsed: false };
	try {
		const parsed = JSON.parse(value);
		const rawCode = parsed["status_code"] ?? parsed["statusCode"];
		const code = rawCode === void 0 ? void 0 : Number(rawCode);
		const message = [
			parsed["status_msg"],
			parsed["statusMsg"],
			parsed["tips"],
			parsed["toast"],
			parsed["message"]
		].map((item) => String(item ?? "")).find(Boolean);
		return {
			parsed: true,
			...code !== void 0 && Number.isFinite(code) ? { code } : {},
			...message ? { message } : {}
		};
	} catch {
		return { parsed: false };
	}
}
/** Desktop Cookie 会话动作统一响应归一 */
function actionResponse(decoded, bodyKey) {
	const envelopeStatus = Number(decoded["statusCode"] ?? 0);
	const payload = decoded["body"];
	const body = bodyKey ? payload?.[bodyKey] : void 0;
	const actionStatus = Number(body?.status ?? 0);
	const checkMessage = String(body?.checkMessage ?? "");
	const checkDetail = parseActionCheckMessage(checkMessage);
	const checkCode = checkDetail.code ?? Number(body?.checkCode ?? 0);
	return {
		statusCode: envelopeStatus || checkCode || actionStatus,
		statusMsg: [
			checkDetail.message,
			checkDetail.parsed ? "" : checkMessage,
			body?.extraInfo,
			decoded["errorDesc"]
		].map((value) => String(value ?? "")).find(Boolean) ?? "",
		...checkCode ? { checkCode } : {}
	};
}
//#endregion
//#region src/inbox/thread.ts
const retryPause = 1e3;
function sleep$3(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
/** 服务端偶发 StatusCodeRPCTimeout(500)，重试缓解；三次仍失败交回上游响应或原生异常 */
async function fetchThreads(ctx, inboxType, limit, cursor) {
	let last;
	for (let attempt = 0; attempt < 3; attempt++) {
		try {
			const res = await ctx.transport.sendCookieProto(203, inboxType, "/v2/message/get_by_user_init", { inbox: {
				convLimit: limit,
				msgLimit: limit,
				cursor
			} }, ctx.deviceId);
			if (Number(res["statusCode"] ?? 0) === 0) return res;
			last = res;
		} catch (error) {
			if (attempt === 2) throw error;
		}
		if (attempt < 2) await sleep$3(retryPause);
	}
	return err(last);
}
/** Desktop Cookie cmd=203。实测 inboxType=1 返回群聊及普通私信;不依赖 Creator IM token。循环翻页拉全量。 */
async function listCookieThreads(ctx, options = {}) {
	const limit = options.count ?? 20;
	const threads = [];
	for (let cursor = options.cursor ?? 0;;) {
		const inbox = (await fetchThreads(ctx, options.inboxType ?? 1, limit, cursor))["body"]?.["inbox"];
		const rawMessages = inbox?.messages ?? [];
		const rawConversations = inbox?.conversations ?? [];
		threads.push(...rawConversations.length > 0 ? rawConversations.map((conversation) => mapProtoConversationMeta(conversation, rawMessages, ctx.platformUid)) : rawMessages.map((message) => mapProtoConversation(message, ctx.platformUid)));
		if (!inbox?.hasMore) break;
		const next = Number(inbox.cursor ?? "");
		if (!Number.isFinite(next)) break;
		cursor = next;
	}
	return dedupeThreads(threads);
}
/** cmd=12047, /v1/message/get_recent_stranger_message — 陌生人消息（Desktop Cookie 通道；接口无分页字段） */
async function listStrangerThreads(ctx) {
	const decoded = await ctx.transport.sendCookieProto(12047, 1, "/v1/message/get_recent_stranger_message", { getRecentStrangerMessage: {
		latestStrangerVersion: LONG.fromString("0"),
		earliestStrangerVersion: LONG.fromString("0"),
		source: "code_up",
		newUser: 0,
		bizInfo: ""
	} }, ctx.deviceId);
	if (Number(decoded["statusCode"] ?? 0) !== 0) return err(decoded);
	return dedupeThreads(((decoded["body"]?.["getRecentStrangerMessage"])?.messages ?? []).flatMap((row) => row["messages"] ?? []).map((message) => mapProtoConversation(message, ctx.platformUid)));
}
//#endregion
//#region src/contact/friend.ts
/** familiar/list 单行 → 好友身份（remark_name 优先作昵称；缺 uid 丢弃） */
function familiarOf(raw) {
	const uid = String(raw["uid"] ?? "");
	if (!uid) return void 0;
	const secUid = String(raw["sec_uid"] ?? "");
	return {
		uid,
		...secUid ? { secUid } : {},
		nickname: String(raw["remark_name"] ?? raw["nickname"] ?? "")
	};
}
/** GET /aweme/v1/web/familiar/list/ 循环翻页拉全量好友身份 */
async function fetchFamiliarRows(ctx, options = {}) {
	const rows = [];
	const seen = /* @__PURE__ */ new Set();
	let cursor = options.cursor ?? 0;
	for (;;) {
		const params = fingerprintParams(ctx.http.deviceId, ctx.http.guid);
		params.set("cursor", String(cursor));
		params.set("vcd_count", "0");
		params.set("hotsoon_has_more", "0");
		params.set("only_total", "0");
		params.set("count", String(options.count ?? 100));
		params.set("order_by", "1");
		params.set("need_all_friend", "1");
		params.set("recommend_type", "22");
		const page = (await ctx.http.json(`${site.im}${api.familiar}?${params}`, { headers: { Referer: site.im } })).data;
		if (Number(page?.status_code ?? 0) !== 0) break;
		for (const raw of page.user_list ?? []) {
			const row = familiarOf(raw);
			if (row && !seen.has(row.uid)) {
				seen.add(row.uid);
				rows.push(row);
			}
		}
		if (!page.has_more) break;
		const next = Number(page.cursor ?? 0);
		if (!Number.isFinite(next) || next === cursor) break;
		cursor = next;
	}
	return rows;
}
/** 好友列表：真实接口 familiar/list；无会话 ID，按 uid 交叉匹配会话补齐 */
async function getFriendList(ctx, options = {}) {
	const [rows, threads] = await Promise.all([fetchFamiliarRows(ctx, options), listCookieThreads(ctx, { count: options.count }).catch(() => [])]);
	const byUid = /* @__PURE__ */ new Map();
	for (const thread of threads) if (thread.peer.uid && !byUid.has(thread.peer.uid)) byUid.set(thread.peer.uid, thread);
	return rows.map((row) => {
		const thread = byUid.get(row.uid);
		return {
			uid: row.uid,
			...row.secUid ? { secUid: row.secUid } : {},
			nickname: row.nickname,
			conversationId: thread?.threadId ?? "",
			conversationShortId: thread?.conversationShortId ?? "",
			...thread?.lastMessage ? { lastMessage: thread.lastMessage } : {},
			lastMessageTime: thread?.lastMessage?.createTime ?? thread?.updateTime ?? 0,
			unreadCount: thread?.unreadCount ?? 0
		};
	});
}
function requestOf$1(value) {
	if (!value) return void 0;
	const applicantUid = String(value["userId"] ?? "");
	if (!applicantUid || applicantUid === "0") return void 0;
	const profile = value["profile"];
	const ext = value["ext"];
	const extRecord = ext && typeof ext === "object" ? ext : void 0;
	const nickname = String(profile?.["nickName"] ?? "");
	const avatar = String(profile?.["protrait"] ?? "");
	const requestedAt = String(value["applyTimeSecond"] ?? "");
	const message = String(extRecord?.["apply_reason"] ?? extRecord?.["applyReason"] ?? extRecord?.["message"] ?? "");
	return {
		applicantUid,
		status: Number(value["status"] ?? 1),
		...nickname ? { nickname } : {},
		...avatar ? { avatar } : {},
		...requestedAt && requestedAt !== "0" ? { requestedAt } : {},
		...message ? { message } : {},
		...extRecord ? { ext: extRecord } : {}
	};
}
/** cmd=2048 好友申请列表 */
async function getFriendRequests(ctx, options = {}) {
	const requests = [];
	let cursor = "0";
	for (;;) {
		const decoded = await ctx.transport.sendCookieProto(2048, 0, "/v1/friend/get_receive_apply_list", { getFriendReceiveApplyList: {
			cursor: LONG.fromString(cursor),
			limit: LONG.fromString("100"),
			getTotalCount: true,
			status: options.status ?? 1
		} }, ctx.deviceId);
		if (actionResponse(decoded).statusCode !== 0) return err(decoded);
		const body = decoded["body"]?.["getFriendReceiveApplyList"];
		for (const raw of body?.userList ?? []) {
			const request = requestOf$1(raw);
			if (request) requests.push(request);
		}
		if (!body?.hasMore) return requests;
		const next = String(body.nextCursor ?? "");
		if (!next) return requests;
		cursor = next;
	}
}
/** cmd=2049 审批好友申请 */
async function reviewFriendRequest(ctx, applicantUid, status) {
	return actionResponse(await ctx.transport.sendCookieProto(2049, 0, "/v1/friend/reply_apply", { replyFriendApply: {
		userId: [LONG.fromString(applicantUid)],
		attitude: status,
		ext: {}
	} }, ctx.deviceId), "replyFriendApply");
}
//#endregion
//#region src/contact/stranger.ts
/** 陌生人会话线程 → 陌生人信息 */
function strangerOf(thread) {
	const peer = thread.peer;
	if (!peer.uid) return void 0;
	return {
		uid: peer.uid,
		...peer.secUid ? { secUid: peer.secUid } : {},
		...peer.nickname ? { nickname: peer.nickname } : {},
		conversationId: thread.threadId,
		conversationShortId: thread.conversationShortId ?? "",
		...thread.lastMessage ? { lastMessage: thread.lastMessage } : {},
		lastMessageTime: thread.lastMessage?.createTime ?? thread.updateTime,
		unreadCount: thread.unreadCount
	};
}
/** 陌生人会话列表 */
async function getStrangerList(ctx) {
	return (await listStrangerThreads(ctx)).map(strangerOf).filter((stranger) => stranger !== void 0);
}
//#endregion
//#region src/contact/users.ts
/** im/user/info：按 secUid 批量拉资料（昵称/头像/签名/关系，群昵称不随 605 下发只能在此查），50 一批 */
async function userInfo(http, secUids) {
	const result = [];
	const list = [...new Set(secUids.filter(Boolean))];
	for (let offset = 0; offset < list.length; offset += 50) {
		const batch = list.slice(offset, offset + 50);
		const params = fingerprintParams(http.deviceId, http.guid);
		params.set("iid", http.installId);
		const form = new FormData();
		form.append("sec_user_ids", JSON.stringify(batch));
		const res = await http.json(`${site.im}${api.userInfo}?${params}`, {
			method: "POST",
			body: form,
			headers: { Referer: site.im }
		});
		if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
		for (const raw of res.data.data ?? []) {
			const item = infoOf(raw);
			if (item) result.push(item);
		}
	}
	return result;
}
function infoOf(raw) {
	const secUid = typeof raw["sec_uid"] === "string" ? raw["sec_uid"] : "";
	if (!secUid) return void 0;
	const avatar = avatarOf(raw["avatar_thumb"]);
	return {
		uid: String(raw["uid"] ?? ""),
		secUid,
		...typeof raw["nickname"] === "string" && raw["nickname"] ? { nickname: raw["nickname"] } : {},
		...avatar ? { avatar } : {},
		...typeof raw["signature"] === "string" && raw["signature"] ? { signature: raw["signature"] } : {},
		...typeof raw["short_id"] === "string" && raw["short_id"] ? { shortId: raw["short_id"] } : {},
		...typeof raw["unique_id"] === "string" && raw["unique_id"] ? { uniqueId: raw["unique_id"] } : {},
		...raw["follow_status"] != null ? { followStatus: Number(raw["follow_status"]) } : {},
		...raw["follower_status"] != null ? { followerStatus: Number(raw["follower_status"]) } : {},
		...typeof raw["is_block"] === "boolean" ? { isBlock: raw["is_block"] } : {},
		...raw["im_activeness"] != null ? { imActiveness: Number(raw["im_activeness"]) } : {},
		raw
	};
}
/** 批量取昵称/头像，按 secUid 索引（内部补全群昵称、发送者昵称用） */
async function getUserProfiles(http, secUids) {
	const result = /* @__PURE__ */ new Map();
	for (const item of await userInfo(http, secUids)) {
		if (!item.nickname && !item.avatar) continue;
		result.set(item.secUid, {
			...item.nickname ? { nickname: item.nickname } : {},
			...item.avatar ? { avatar: item.avatar } : {}
		});
	}
	return result;
}
/** profile/scene：对话场景资料（响应顶层即用户对象，字段比 profile/other 少） */
async function profileScene(http, secUid) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("sec_user_id", secUid);
	params.set("wish_flag", "1");
	params.set("scene", "5");
	params.set("source", "4");
	return profileOf((await http.json(`${site.edge}${api.profileScene}?${params}`, { headers: { Referer: site.referer } })).data);
}
/** profile/other：完整资料（user 字段打包，含地域/年龄等原始字段） */
async function profileOther(http, secUid) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("source", "channel_pc_web");
	params.set("sec_user_id", secUid);
	params.set("personal_center_strategy", "1");
	params.set("profile_other_record_enable", "1");
	params.set("land_to", "1");
	return profileOf((await http.json(`${site.edge}${api.profileOther}?${params}`, { headers: { Referer: site.referer } })).data.user);
}
/** profile/self：自己的完整资料（响应顶层 user 字段；imdesktop 版无 status_code，以 user 是否出现为准） */
async function profileSelf(http) {
	const params = fingerprintParams(http.deviceId, http.guid);
	return profileOf((await http.json(`${site.im}${api.profileSelf}?${params}`, { headers: { Referer: site.referer } })).data.user);
}
function profileOf(raw) {
	const avatar = avatarOf(raw["avatar_thumb"]) ?? avatarOf(raw["avatar_larger"]) ?? avatarOf(raw["avatar_168x168"]);
	return {
		uid: String(raw["uid"] ?? ""),
		secUid: String(raw["sec_uid"] ?? ""),
		...typeof raw["nickname"] === "string" && raw["nickname"] ? { nickname: raw["nickname"] } : {},
		...typeof raw["signature"] === "string" && raw["signature"] ? { signature: raw["signature"] } : {},
		...avatar ? { avatar } : {},
		...typeof raw["unique_id"] === "string" && raw["unique_id"] ? { uniqueId: raw["unique_id"] } : {},
		...raw["following_count"] != null ? { followingCount: Number(raw["following_count"]) } : {},
		...raw["follower_count"] != null ? { followerCount: Number(raw["follower_count"]) } : {},
		...raw["follow_status"] != null ? { followStatus: Number(raw["follow_status"]) } : {},
		...raw["follower_status"] != null ? { followerStatus: Number(raw["follower_status"]) } : {},
		raw
	};
}
function avatarOf(value) {
	const list = value?.url_list;
	if (!Array.isArray(list)) return void 0;
	return list.find((url) => typeof url === "string" && url !== "");
}
//#endregion
//#region src/chat/member.ts
/** cmd=605 分页拉群成员；服务端按 cursor 推进，游标不前进即按上游返回终止 */
async function getGroupMembers(ctx, address) {
	const members = [];
	let cursor = "0";
	for (;;) {
		const decoded = await ctx.transport.sendCookieProto(605, address.inboxType ?? 0, "/v1/conversation/participants_list", { conversationParticipants: {
			conversationId: address.conversationId,
			conversationShortId: LONG.fromString(address.conversationShortId),
			conversationType: address.conversationType,
			cursor: LONG.fromString(cursor),
			limit: 100
		} }, ctx.deviceId);
		if (actionResponse(decoded, "conversationParticipants").statusCode !== 0) return err(decoded);
		const page = (decoded["body"]?.["conversationParticipants"])?.participantsPage;
		for (const participant of page?.participants ?? []) {
			const uid = String(participant["userId"] ?? "");
			if (!uid) continue;
			const secUid = String(participant["secUid"] ?? "");
			const alias = String(participant["alias"] ?? "");
			const sortOrder = String(participant["sortOrder"] ?? "");
			const leftBlockTime = String(participant["leftBlockTime"] ?? "");
			const ext = participant["ext"];
			members.push({
				uid,
				role: Number(participant["role"] ?? 0),
				...secUid ? { secUid } : {},
				...alias ? { alias } : {},
				...sortOrder ? { sortOrder } : {},
				...participant["blocked"] !== void 0 ? { blocked: Number(participant["blocked"]) } : {},
				...leftBlockTime ? { leftBlockTime } : {},
				...ext && typeof ext === "object" ? { ext } : {}
			});
		}
		if (!page?.hasMore) return members;
		const next = String(page.cursor ?? "");
		if (!next) return members;
		cursor = next;
	}
}
//#endregion
//#region src/chat/group.ts
const act = {
	add: {
		cmd: 650,
		path: "/v1/conversation/add_participants",
		key: "conversationAddParticipants"
	},
	remove: {
		cmd: 651,
		path: "/v1/conversation/remove_participants",
		key: "conversationRemoveParticipants"
	},
	leave: {
		cmd: 652,
		path: "/v1/conversation/leave",
		key: "leaveConversation"
	},
	del: {
		cmd: 603,
		path: "/v1/conversation/delete",
		key: "deleteConversation"
	},
	name: {
		cmd: 902,
		path: "/v1/conversation/set_conversation_core_info",
		key: "setConversationCoreInfo",
		inbox: 1
	},
	setting: {
		cmd: 921,
		path: "/v1/conversation/set_setting_info",
		key: "setConversationSettingInfo"
	}
};
/** 地址三件套：短 id 为 int64，必须以 Long 下发 */
function addr(address) {
	return {
		conversationId: address.conversationId,
		conversationShortId: address.conversationShortId ? LONG.fromString(address.conversationShortId) : void 0,
		conversationType: address.conversationType
	};
}
/** 动作请求：地址公共字段 + 业务字段统一包在当前动作的响应体键下 */
async function send$2(ctx, action, address, payload) {
	return ctx.transport.sendCookieProto(action.cmd, action.inbox ?? address.inboxType ?? 1, action.path, { [action.key]: {
		...addr(address),
		...payload
	} }, ctx.deviceId);
}
function bodyOf(decoded, key) {
	return decoded["body"]?.[key];
}
/** cmd=650 拉人入群；响应回读成功/失败名单 */
async function addGroupMembers(ctx, address, uids) {
	const decoded = await send$2(ctx, act.add, address, {
		participants: uids.map((uid) => LONG.fromString(uid)),
		bizExt: {
			invitation: JSON.stringify({
				invitee: { source_app_id: 6383 },
				invitor: { im_user_id: Number(ctx.platformUid) },
				source_type: 6
			}),
			source_type: "6",
			ticket: ""
		}
	});
	const result = actionResponse(decoded, act.add.key);
	const body = bodyOf(decoded, act.add.key);
	return {
		...result,
		...body?.successParticipants?.length ? { success: body.successParticipants.map(String) } : {},
		...body?.failedParticipants?.length ? { failed: body.failedParticipants.map(String) } : {}
	};
}
/** cmd=651 移出群成员 */
async function removeGroupMembers(ctx, address, uids) {
	return actionResponse(await send$2(ctx, act.remove, address, { participants: uids.map((uid) => LONG.fromString(uid)) }), act.remove.key);
}
/** cmd=652 退出群聊（响应为空 body） */
async function leaveGroup(ctx, address) {
	return actionResponse(await send$2(ctx, act.leave, address, {}), act.leave.key);
}
/** cmd=603 删除会话（响应为空 body） */
async function deleteConversation(ctx, address, options = {}) {
	return actionResponse(await send$2(ctx, act.del, address, {
		lastMessageIndex: LONG.fromString(options.lastMessageIndex ?? "0"),
		badgeCount: 0
	}), act.del.key);
}
/** cmd=902 设置群名 */
async function setGroupName(ctx, address, name) {
	return actionResponse(await send$2(ctx, act.name, address, {
		name,
		isNameSet: true
	}), act.name.key);
}
/** cmd=921 会话设置（置顶/免打扰/收藏），响应回读完整设置 */
async function setConversationSetting(ctx, address, input) {
	const decoded = await send$2(ctx, act.setting, address, {
		...input.setStickOnTop != null ? { setStickOnTop: input.setStickOnTop } : {},
		...input.setMute != null ? { setMute: input.setMute } : {},
		...input.setFavorite != null ? { setFavorite: input.setFavorite } : {}
	});
	const result = actionResponse(decoded, act.setting.key);
	const setting = bodyOf(decoded, act.setting.key)?.["conversationSettingInfo"];
	return {
		...result,
		...setting ? { setting } : {}
	};
}
/** cmd=609 创建群聊，返回创建出的会话 */
async function createGroup(ctx, options) {
	const name = options.name ?? "";
	const description = options.description ?? "";
	const decoded = await ctx.transport.sendCookieProto(609, 1, "/v2/conversation/create", { createConversationV2: {
		conversationType: 2,
		participants: options.participantUids.map((uid) => LONG.fromString(uid)),
		name,
		description,
		bizExt: {
			group_type: "1000",
			show_at_profile: "1",
			group_name: name,
			group_desc: description
		},
		ext: {
			"a:s_group_type": "1000",
			"a:s_group_category": "2"
		}
	} }, ctx.deviceId);
	const result = actionResponse(decoded, "createConversationV2");
	const conv = bodyOf(decoded, "createConversationV2")?.["conversation"];
	if (!conv) return result;
	return {
		...result,
		group: {
			conversationId: String(conv.conversationId ?? ""),
			conversationShortId: String(conv.conversationShortId ?? ""),
			conversationType: Number(conv.conversationType ?? 2),
			isGroup: true,
			name,
			members: [],
			lastMessageTime: 0
		}
	};
}
//#endregion
//#region src/media/play.ts
/** maya batch_play_info：用消息视频的 tkey 换加密 CDN 地址（私信视频协议不直发播放地址） */
async function getVideoUrl(http, tkey) {
	if (!tkey.trim()) err({ tkey });
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	const res = await http.json(`${site.im}${api.playInfo}?${params}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Referer: site.im
		},
		body: JSON.stringify({
			req_infos: [{
				tos_key: tkey,
				type: 2
			}],
			with_caption: true
		})
	});
	const url = res.data?.data?.play_infos?.[0]?.encrypted_url;
	if (!url?.main_url) err(res.data);
	return {
		mainUrl: url.main_url,
		...url.backup_url ? { backupUrl: url.backup_url } : {},
		...url.expire_time ? { expireTime: url.expire_time } : {}
	};
}
/** multi/aweme/detail:按 awemeId 批量拉消息中的作品详情（视频/图文） */
async function awemeDetail(http, awemeIds, options = {}) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("aweme_ids", JSON.stringify(awemeIds));
	params.set("origin_type", options.originType ?? "chat");
	params.set("request_source", String(options.requestSource ?? 3));
	if (options.conversationShortId) params.set("conversation_short_id", options.conversationShortId);
	return ((await http.json(`${site.edge}${api.awemeDetail}?${params}`, {
		method: "POST",
		headers: {
			Referer: site.referer,
			"Content-Type": "application/json"
		},
		body: "{}"
	})).data?.aweme_details ?? []).map(awemeOf);
}
function urlsOf$1(v) {
	const list = v?.url_list;
	if (!Array.isArray(list)) return void 0;
	return list.filter((u) => typeof u === "string" && u !== "");
}
function awemeOf(raw) {
	const r = raw;
	const video = r["video"];
	const author = r["author"];
	const avatar = urlsOf$1(author?.["avatar_thumb"])?.[0];
	const playUrls = urlsOf$1(video?.["play_addr"]);
	const coverUrls = urlsOf$1(video?.["cover"]);
	return {
		awemeId: String(r["aweme_id"] ?? ""),
		...typeof r["desc"] === "string" && r["desc"] ? { desc: r["desc"] } : {},
		...r["create_time"] != null ? { createTime: Number(r["create_time"]) } : {},
		...playUrls ? { playUrls } : {},
		...coverUrls ? { coverUrls } : {},
		...author && (author["sec_uid"] || author["nickname"] || avatar) ? { author: {
			...typeof author["sec_uid"] === "string" && author["sec_uid"] ? { secUid: author["sec_uid"] } : {},
			...typeof author["nickname"] === "string" && author["nickname"] ? { nickname: author["nickname"] } : {},
			...avatar ? { avatar } : {}
		} } : {},
		raw: r
	};
}
//#endregion
//#region src/message/content.ts
/** messageType=1 文本 content（HTTP SDK 可投递） */
function buildLegacyTextContent(text) {
	return JSON.stringify({ text });
}
/** 创作者 Web 文本消息 content（messageType=7，HTTP 路径 aweType=774） */
function buildCreatorTextContent(text) {
	return JSON.stringify({
		text,
		aweType: 774
	});
}
/** Desktop IM 文本 content；字段和值与 jumpbyte 的成功 HAR 保持一致。 */
function buildDesktopTextContent(text, mentions = []) {
	return JSON.stringify({
		aweType: 700,
		type: 0,
		instruction_type: 0,
		item_type_local: -1,
		richTextInfos: mentions.map((mention) => ({
			infoType: 1,
			location: mention.location,
			length: mention.length,
			info: {
				uid: mention.uid,
				...mention.conId ? { con_id: mention.conId } : {}
			}
		})),
		text,
		createdAt: 0,
		is_card: false,
		msgHint: ""
	});
}
/**
* Desktop IM 文本 + @所有人 content：占位「@所有人 」从开头插入（length=5、location=0）。
* richTextInfos 镜像收侧实测样本（infoType=4 mention_label 标记 + infoType=2 加粗），
* font_weight 为数字（对齐 HAR 权威样本）——发侧 @all 判定另靠 ext s:mentioned_users="0"。
*/
function buildAtAllTextContent(text) {
	return JSON.stringify({
		aweType: 700,
		type: 0,
		instruction_type: 0,
		item_type_local: -1,
		richTextInfos: [{
			info: { mention_label: "1" },
			infoType: 4,
			length: 5,
			location: 0
		}, {
			info: { font_weight: 2 },
			infoType: 2,
			length: 5,
			location: 0
		}],
		text: "@所有人 " + text,
		createdAt: 0,
		is_card: false,
		msgHint: ""
	});
}
/** 文本 + @ 提及合成 content：@ 渲染「@昵称 」占位（无昵称退回 uid），位置记录供 richTextInfos 使用 */
function textWithAts(text, ats, conId) {
	const list = ats ?? [];
	if (!list.length) return {
		content: text,
		mentions: []
	};
	let content = text;
	const mentions = [];
	for (const at of list) {
		const piece = `@${at.nickname ?? at.uid} `;
		mentions.push({
			uid: at.uid,
			conId,
			location: content.length,
			length: piece.length
		});
		content += piece;
	}
	return {
		content: buildDesktopTextContent(content, mentions),
		mentions
	};
}
/** 构造引用元数据（refMsgInfo）：任意消息类型均可引用，hint 承载被引用消息类型与摘要 */
function buildReference(meta) {
	const reference = {
		referencedMessageId: meta.referencedMessageId,
		hint: JSON.stringify({
			refmsg_type: meta.referencedMessageType,
			content: meta.referencedText ?? "",
			refmsg_uid: meta.referencedUid,
			refmsg_sec_uid: meta.referencedSecUid ?? "",
			nickname: meta.nickname ?? "",
			refmsg_content: "",
			version: 0,
			itemId: "",
			scene_type: 0
		})
	};
	if (meta.rootMessageId) reference.rootMessageId = meta.rootMessageId;
	if (meta.rootMessageConvIndex) reference.rootMessageConvIndex = meta.rootMessageConvIndex;
	return reference;
}
/**
* 将简单 `{"text":"..."}` 或纯文本转为 type=7 内容。
* HTTP 默认 aweType=774；desktop 发送使用 normalizeDesktopTextMessageContent（aweType=700）。
*/
function normalizeTextMessageContent(content, msgType) {
	if (msgType === 1) {
		try {
			if (JSON.parse(content).text != null) return content;
		} catch {
			return buildLegacyTextContent(content);
		}
		return content;
	}
	if (msgType !== 7) return content;
	try {
		const j = JSON.parse(content);
		if (j.text != null && j.aweType == null && !("ai_ext" in j)) return buildCreatorTextContent(j.text);
		if (j.aweType != null || j.ai_ext != null) return content;
	} catch {
		return buildCreatorTextContent(content);
	}
	return content;
}
/** 仅将普通文本转换成 Desktop IM 模板，富媒体保持原样。 */
function normalizeDesktopTextMessageContent(content, msgType) {
	if (msgType !== 7) return normalizeTextMessageContent(content, msgType);
	try {
		const value = JSON.parse(content);
		if (typeof value !== "object" || value === null || Array.isArray(value)) return buildDesktopTextContent(content);
		const record = value;
		const keys = Object.keys(record);
		return typeof record["text"] === "string" && keys.every((key) => [
			"text",
			"aweType",
			"type",
			"richTextInfos"
		].includes(key)) && (!Array.isArray(record["richTextInfos"]) || record["richTextInfos"].length === 0) ? buildDesktopTextContent(record["text"]) : content;
	} catch {
		return buildDesktopTextContent(content);
	}
}
//#endregion
//#region src/bot/address.ts
/** chatId：`type:shortId:conversationId` 的不透明串，格式不承诺稳定 */
function chatIdOf(src) {
	if ("threadId" in src && src.threadId) return `50:${src.threadShortId ?? src.conversationShortId ?? ""}:${src.threadId}`;
	return `${src.conversationType}:${src.conversationShortId}:${src.conversationId}`;
}
function toAddress(chatId) {
	const [type, shortId, ...rest] = chatId.split(":");
	const conversationId = rest.join(":");
	if (!type || !shortId || !conversationId) return err({ chatId });
	return {
		conversationId,
		conversationShortId: shortId,
		conversationType: Number(type)
	};
}
/** 由收到的消息提取引用元数据：任意消息类型均可被引用，类型原样透传 */
function referenceOf(msg) {
	return buildReference({
		referencedMessageId: msg.serverMessageId ?? "",
		referencedMessageType: msg.messageType,
		referencedUid: msg.senderUid,
		referencedSecUid: msg.senderSecUid,
		nickname: msg.senderNickname,
		referencedText: msg.text,
		rootMessageId: msg.reference?.rootMessageId
	});
}
//#endregion
//#region src/media/image.ts
/**
* 解密单个 cenc-aes-ctr sample。受保护子区共享同一条连续计数器流；
* clear 区间不消耗计数流。
*/
function decryptCencSample(data, keyInput, ivInput, subsamples = []) {
	const key = Buffer.from(keyInput);
	if (key.length !== 16) err({ length: key.length });
	if (ivInput.length !== 8 && ivInput.length !== 16) err({ length: ivInput.length });
	const iv = Buffer.alloc(16);
	Buffer.from(ivInput).copy(iv);
	const source = Buffer.from(data);
	if (subsamples.length === 0) {
		const cipher = createCipheriv("aes-128-ctr", key, iv);
		return Buffer.concat([cipher.update(source), cipher.final()]);
	}
	const protectedChunks = [];
	let pos = 0;
	for (const sample of subsamples) {
		if (sample.clear < 0 || sample.protected < 0 || pos + sample.clear + sample.protected > source.length) err({
			clear: sample.clear,
			protected: sample.protected
		});
		pos += sample.clear;
		protectedChunks.push(source.subarray(pos, pos + sample.protected));
		pos += sample.protected;
	}
	const cipher = createCipheriv("aes-128-ctr", key, iv);
	const decrypted = Buffer.concat([cipher.update(Buffer.concat(protectedChunks)), cipher.final()]);
	const output = Buffer.alloc(source.length);
	pos = 0;
	let decryptedPos = 0;
	for (const sample of subsamples) {
		source.copy(output, pos, pos, pos + sample.clear);
		pos += sample.clear;
		decrypted.copy(output, pos, decryptedPos, decryptedPos + sample.protected);
		pos += sample.protected;
		decryptedPos += sample.protected;
	}
	source.copy(output, pos, pos);
	return output;
}
const PNG = Buffer.from([
	137,
	80,
	78,
	71,
	13,
	10,
	26,
	10
]);
const HEIC = /* @__PURE__ */ new Set([
	"heic",
	"heix",
	"hevc",
	"hevx",
	"heim",
	"heis",
	"mif1",
	"msf1"
]);
/** 魔数嗅探：顺序即优先级，未命中才算 unknown */
const formats = [
	["webp", (b) => b.length >= 12 && b.subarray(0, 4).toString() === "RIFF" && b.subarray(8, 12).toString() === "WEBP"],
	["jpeg", (b) => b.length >= 2 && b[0] === 255 && b[1] === 216],
	["png", (b) => b.length >= 8 && b.subarray(0, 8).equals(PNG)],
	["gif", (b) => b.length >= 6 && (b.subarray(0, 6).toString() === "GIF87a" || b.subarray(0, 6).toString() === "GIF89a")],
	["heic", (b) => {
		if (b.length < 12 || b.subarray(4, 8).toString() !== "ftyp") return false;
		for (let offset = 8; offset + 4 <= Math.min(b.length, 32); offset += 4) if (HEIC.has(b.subarray(offset, offset + 4).toString())) return true;
		return false;
	}]
];
function sniffImageFormat(data) {
	const b = Buffer.from(data);
	return formats.find(([, match]) => match(b))?.[0] ?? "unknown";
}
//#endregion
//#region src/media/json.ts
/** 服务端字段类型不稳定，先宽松读一层 record 再逐字段收窄 */
function asRecord$2(value) {
	return value && typeof value === "object" ? value : {};
}
//#endregion
//#region src/media/sign.ts
/**
* VOD 走 AWS Signature V4：签名串与 query 必须逐字节一致，
* 故规范化/派生集中在此，调用方只负责拼业务参数。
*/
function hashHex(data) {
	return createHash("sha256").update(data).digest("hex");
}
function hmac(key, value) {
	return createHmac("sha256", key).update(value).digest();
}
function rfc3986(value) {
	return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}
function canonicalUploadQuery(query) {
	return Object.keys(query).sort().map((key) => `${rfc3986(key)}=${rfc3986(query[key])}`).join("&");
}
/** ByteDance VOD 上传用的纯 AWS Signature V4 实现 */
function signVodRequest(options) {
	const canonicalQuery = canonicalUploadQuery(options.query);
	const amzDate = options.date.toISOString().replace(/[:-]|\.\d{3}/g, "");
	const dateStamp = amzDate.slice(0, 8);
	const payloadHash = hashHex(options.body ?? /* @__PURE__ */ new Uint8Array());
	const headers = {
		"x-amz-date": amzDate,
		"x-amz-security-token": options.credentials.sessionToken
	};
	if (options.method === "POST") headers["x-amz-content-sha256"] = payloadHash;
	const headerNames = Object.keys(headers).sort();
	const canonicalHeaders = headerNames.map((name) => `${name}:${headers[name]}\n`).join("");
	const signedHeaders = headerNames.join(";");
	const canonicalRequest = [
		options.method,
		"/",
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash
	].join("\n");
	const scope = `${dateStamp}/${vod.region}/${vod.service}/aws4_request`;
	const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${hashHex(canonicalRequest)}`;
	let signingKey = hmac(`AWS4${options.credentials.secretAccessKey}`, dateStamp);
	signingKey = hmac(signingKey, vod.region);
	signingKey = hmac(signingKey, vod.service);
	signingKey = hmac(signingKey, "aws4_request");
	const signature = hmac(signingKey, stringToSign).toString("hex");
	return {
		canonicalQuery,
		headers,
		authorization: `AWS4-HMAC-SHA256 Credential=${options.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
	};
}
/** ApplyUpload 的 s 参数只需不可预测，避免 CDN 命中上一轮残留对象 */
function randomId(length) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
	return [...randomBytes(length)].map((byte) => alphabet[byte % 36]).join("");
}
//#endregion
//#region src/media/vod.ts
/** 分片上传单段大小，需与 ApplyUpload 声明的 FileSize 协商一致 */
const chunk$1 = vod.part;
/** 提交阶段按文件类型下发转码/加密策略；object 走 TOS 服务端 GCM，无需 process */
const processes = {
	object: () => [],
	video: () => [{
		name: "Encryption",
		input: {
			Config: {
				copies: "cipher_v2",
				aes_chunk_size: "524288"
			},
			PolicyParams: { "policy-set": "medium" }
		}
	}],
	image: (format) => {
		return [{
			name: "Encryption",
			input: {
				Config: { copies: "cipher_v2" },
				PolicyParams: format === "gif" ? {
					"policy-set": "still",
					"still-width": "480",
					"still-height": "480"
				} : { "policy-set": "check,thumb,medium,large" }
			}
		}];
	}
};
function uploadProcessFunctions(fileType, imageFormat) {
	return processes[fileType](imageFormat);
}
/** Cookie 鉴权 STS → 签名 VOD → TOS 上传工作流中的 VOD 侧（HTTP 统一经 Http） */
var Vod = class {
	http;
	userId;
	constructor(http, userId) {
		this.http = http;
		this.userId = userId;
	}
	async credentials(configKey = "public_image_config") {
		const params = fingerprintParams(this.userId, randomBytes(16).toString("hex"));
		const response = await this.http.request(`${site.web}${api.uploadConfig}?${params}`, {
			method: "GET",
			headers: { Referer: site.referer }
		});
		const json = asRecord$2(JSON.parse(response.text));
		const config = asRecord$2(json[configKey]);
		const credentials = {
			accessKeyId: String(config["access_key_id"] ?? ""),
			secretAccessKey: String(config["secret_access_key"] ?? ""),
			sessionToken: String(config["session_token"] ?? ""),
			spaceName: String(config["space_name"] ?? "")
		};
		if (!response.ok) err(json);
		if (!credentials.accessKeyId || !credentials.secretAccessKey || !credentials.spaceName) err(config);
		return credentials;
	}
	async apply(credentials, space, fileType, fileSize) {
		const query = {
			Action: "ApplyUploadInner",
			Version: "2020-11-19",
			SpaceName: space,
			FileType: fileType,
			IsInner: "1",
			NeedFallback: "true",
			FileSize: String(fileSize),
			s: randomId(11),
			...fileType === "object" ? { OpenGcmEnc: "true" } : {}
		};
		const result = asRecord$2((await this.signed("GET", query, void 0, credentials))["Result"]);
		const direct = asRecord$2(result["UploadAddress"]);
		const directStores = direct["StoreInfos"];
		const directHosts = direct["UploadHosts"];
		const inner = asRecord$2(result["InnerUploadAddress"]);
		const nodes = inner["UploadNodes"];
		if (!nodes?.length && directStores?.length && directHosts?.length && fileType !== "object") {
			const store = asRecord$2(directStores[0]);
			return {
				storeUri: String(store["StoreUri"] ?? ""),
				authorization: String(store["Auth"] ?? ""),
				host: String(directHosts[0]),
				sessionKey: String(direct["SessionKey"] ?? "")
			};
		}
		const node = asRecord$2(nodes?.[0]);
		const stores = node["StoreInfos"];
		const store = asRecord$2(stores?.[0]);
		const address = {
			storeUri: String(store["StoreUri"] ?? ""),
			authorization: String(store["Auth"] ?? ""),
			host: String(node["UploadHost"] ?? ""),
			sessionKey: String(node["SessionKey"] ?? ""),
			uploadHeaders: Object.fromEntries(Object.entries(asRecord$2(node["UploadHeader"])).map(([key, value]) => [key, String(value)]))
		};
		if (fileType === "object") {
			address.gcmMode = String(asRecord$2(result["SDKParam"])["server_gcm_encryption_mode"] ?? "");
			address.encryptionKey = String(asRecord$2(inner["AdvanceOption"])["EncryptionKey"] ?? "");
			if (!address.gcmMode || !address.encryptionKey) err(address);
		}
		if (!address.storeUri || !address.authorization || !address.host || !address.sessionKey) err(address);
		return address;
	}
	async commit(credentials, sessionKey, fileType, imageFormat, address) {
		const body = Buffer.from(JSON.stringify({
			SessionKey: sessionKey,
			Functions: uploadProcessFunctions(fileType, imageFormat),
			...address?.gcmMode ? {
				EncryptionMode: address.gcmMode,
				EncryptionKey: address.encryptionKey
			} : {}
		}));
		const results = asRecord$2((await this.signed("POST", {
			Action: "CommitUploadInner",
			Version: "2020-11-19",
			SpaceName: credentials.spaceName
		}, body, credentials))["Result"])["Results"];
		const encryption = asRecord$2(asRecord$2(results?.[0])["Encryption"]);
		const extra = asRecord$2(encryption["Extra"]);
		const committed = {
			uri: String(encryption["Uri"] ?? ""),
			secretKey: String(encryption["SecretKey"] ?? ""),
			sourceMd5: String(encryption["SourceMd5"] ?? "")
		};
		const imageSize = Number(extra["img_size"]);
		const imageWidth = Number(extra["img_width"]);
		const imageHeight = Number(extra["img_height"]);
		if (Number.isFinite(imageSize) && imageSize > 0) committed.imageSize = imageSize;
		if (Number.isFinite(imageWidth) && imageWidth > 0) committed.imageWidth = imageWidth;
		if (Number.isFinite(imageHeight) && imageHeight > 0) committed.imageHeight = imageHeight;
		if (!committed.uri || !committed.secretKey) err(committed);
		return committed;
	}
	async signed(method, query, body, credentials) {
		const signed = signVodRequest({
			method,
			query,
			...body ? { body } : {},
			credentials,
			date: /* @__PURE__ */ new Date()
		});
		const response = await this.http.request(`${site.vod}?${signed.canonicalQuery}`, {
			method,
			headers: {
				...signed.headers,
				Authorization: signed.authorization,
				"User-Agent": PC_UA,
				...body ? { "Content-Type": "text/plain;charset=UTF-8" } : {}
			},
			...body ? { body: new Uint8Array(body) } : {}
		});
		const json = asRecord$2(JSON.parse(response.text));
		if (!response.ok) err(json);
		const error = asRecord$2(asRecord$2(json["ResponseMetadata"])["Error"]);
		if (error["Code"] || error["CodeN"]) err(json);
		return json;
	}
};
//#endregion
//#region src/media/tos.ts
/** TOS 以 CRC32 校验对象/分片完整性，Content-CRC32 必须为 8 位小写 hex */
let crcTable;
function table$1() {
	if (crcTable) return crcTable;
	crcTable = /* @__PURE__ */ new Uint32Array(256);
	for (let n = 0; n < 256; n += 1) {
		let c = n;
		for (let k = 0; k < 8; k += 1) c = c & 1 ? 3988292384 ^ c >>> 1 : c >>> 1;
		crcTable[n] = c >>> 0;
	}
	return crcTable;
}
function crc32Hex(data) {
	let crc = 4294967295;
	const values = table$1();
	for (const byte of data) crc = values[(crc ^ byte) & 255] ^ crc >>> 8;
	return ((crc ^ 4294967295) >>> 0).toString(16).padStart(8, "0");
}
/** TOS 存储侧：对象直传与分片上传，鉴权头由 ApplyUpload 下发 */
var Tos = class {
	http;
	userId;
	constructor(http, userId) {
		this.http = http;
		this.userId = userId;
	}
	async put(address, data) {
		const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}`, {
			method: "POST",
			headers: {
				...this.headers(address.authorization, crc32Hex(data)),
				...address.uploadHeaders ?? {},
				...address.gcmMode ? {
					"X-Upload-Server-Gcm-Encryption-Mode": address.gcmMode,
					"X-Upload-Server-Gcm-Encryption-Key": address.encryptionKey ?? ""
				} : {}
			},
			body: new Uint8Array(data)
		});
		const result = asRecord$2(JSON.parse(response.text));
		if (!response.ok || Number(result["code"]) !== 2e3) err(result);
	}
	async init(address) {
		const boundary = `----WebKitFormBoundary${randomId(16)}`;
		const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}?phase=init`, {
			method: "POST",
			headers: {
				...this.headers(address.authorization),
				"Content-Type": `multipart/form-data; boundary=${boundary}`
			},
			body: `--${boundary}--\r\n`
		});
		const result = asRecord$2(JSON.parse(response.text));
		const uploadId = String(asRecord$2(result["data"])["uploadid"] ?? "");
		if (!response.ok || Number(result["code"]) !== 2e3 || !uploadId) err(result);
		return uploadId;
	}
	async part(address, uploadId, part, crc, data) {
		const query = new URLSearchParams({
			uploadid: uploadId,
			part_number: String(part),
			phase: "transfer"
		});
		const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}?${query}`, {
			method: "POST",
			headers: {
				...this.headers(address.authorization, crc),
				"Content-Disposition": "attachment; filename=\"undefined\""
			},
			body: new Uint8Array(data)
		});
		const result = asRecord$2(JSON.parse(response.text));
		if (!response.ok || Number(result["code"]) !== 2e3) err(result);
	}
	async finish(address, uploadId, manifest) {
		const query = new URLSearchParams({
			phase: "finish",
			uploadid: uploadId
		});
		const response = await this.http.request(`https://${address.host}${api.upload}${address.storeUri}?${query}`, {
			method: "POST",
			headers: {
				...this.headers(address.authorization),
				"Content-Type": "text/plain;charset=UTF-8"
			},
			body: manifest
		});
		const result = asRecord$2(JSON.parse(response.text));
		if (!response.ok || Number(result["code"]) !== 2e3) err(result);
	}
	headers(authorization, crc) {
		const headers = {
			Authorization: authorization,
			"Content-Type": "application/octet-stream",
			"X-Storage-U": this.userId,
			"User-Agent": PC_UA
		};
		if (crc) headers["Content-CRC32"] = crc;
		return headers;
	}
};
//#endregion
//#region src/media/upload.ts
/** commit 未回传像素尺寸时从图片头兜底解析 */
function imageSize(data) {
	const b = Buffer.from(data);
	if (b.length >= 24 && b.subarray(1, 4).toString() === "PNG") return {
		width: b.readUInt32BE(16),
		height: b.readUInt32BE(20)
	};
	if (b.length > 4 && b[0] === 255 && b[1] === 216) {
		let pos = 2;
		while (pos + 9 < b.length) {
			if (b[pos] !== 255) {
				pos += 1;
				continue;
			}
			const marker = b[pos + 1];
			if (marker >= 192 && marker <= 195) return {
				width: b.readUInt16BE(pos + 7),
				height: b.readUInt16BE(pos + 5)
			};
			const size = b.readUInt16BE(pos + 2);
			if (size < 2) break;
			pos += 2 + size;
		}
	}
	if (b.length >= 10 && (b.subarray(0, 6).toString() === "GIF87a" || b.subarray(0, 6).toString() === "GIF89a")) return {
		width: b.readUInt16LE(6),
		height: b.readUInt16LE(8)
	};
	return {
		width: 0,
		height: 0
	};
}
/** Cookie 鉴权 STS → 签名 VOD → TOS 上传工作流 */
var Uploader = class {
	vod;
	tos;
	constructor(http, userId) {
		this.vod = new Vod(http, userId);
		this.tos = new Tos(http, userId);
	}
	async uploadImage(data) {
		if (data.length === 0) err({ bytes: data.length });
		const format = sniffImageFormat(data);
		if (format === "unknown") err({ format });
		const credentials = await this.vod.credentials();
		const address = await this.vod.apply(credentials, credentials.spaceName, "image", data.length);
		await this.tos.put(address, data);
		const committed = await this.vod.commit(credentials, address.sessionKey, "image", format);
		const size = imageSize(data);
		return {
			oid: committed.uri,
			skey: committed.secretKey,
			md5: committed.sourceMd5,
			dataSize: committed.imageSize ?? data.length,
			width: committed.imageWidth ?? size.width,
			height: committed.imageHeight ?? size.height,
			format
		};
	}
	async uploadVideo(data) {
		if (data.length === 0) err({ bytes: data.length });
		const credentials = await this.vod.credentials();
		const address = await this.vod.apply(credentials, credentials.spaceName, "video", data.length);
		const uploadId = await this.tos.init(address);
		const parts = [];
		for (let offset = 0, part = 1; offset < data.length; offset += chunk$1, part += 1) {
			const piece = data.slice(offset, Math.min(offset + chunk$1, data.length));
			const crc = crc32Hex(piece);
			await this.tos.part(address, uploadId, part, crc, piece);
			parts.push(`${part}:${crc}`);
		}
		await this.tos.finish(address, uploadId, parts.join(","));
		const committed = await this.vod.commit(credentials, address.sessionKey, "video");
		return {
			tkey: committed.uri,
			skey: committed.secretKey,
			md5: committed.sourceMd5
		};
	}
	/** 文件上传（object 通道：public_file_config + GCM 服务端加密，≤10MiB） */
	async uploadFile(data, name) {
		if (!name.trim() || data.length === 0 || data.length > 10485760) err({
			name,
			bytes: data.length
		});
		const credentials = await this.vod.credentials("public_file_config");
		const address = await this.vod.apply(credentials, credentials.spaceName, "object", data.length);
		await this.tos.put(address, data);
		const committed = await this.vod.commit(credentials, address.sessionKey, "object", void 0, address);
		return {
			uri: committed.uri,
			skey: committed.secretKey,
			md5: committed.sourceMd5,
			name,
			dataSize: data.length
		};
	}
};
//#endregion
//#region src/bot/ctx.ts
/** 门面共享上下文：HTTP、设备、传输与收发域参数只组装一次，各能力模块按需取用 */
function createCtx(opts) {
	const userId = opts.userId;
	const deviceId = opts.deviceId ?? opts.http.deviceId;
	const log = opts.log ?? createLog({ tag: "im" });
	const transport = new ProtoTransport(opts.http, log);
	return {
		http: opts.http,
		userId,
		deviceId,
		cookies: opts.cookies,
		log,
		transport,
		uploader: new Uploader(opts.http, userId),
		inbox: {
			transport,
			http: opts.http,
			deviceId,
			platformUid: userId
		},
		send: {
			transport,
			deviceId,
			log,
			http: opts.http,
			userId,
			cookies: opts.cookies
		}
	};
}
//#endregion
//#region src/bot/nick.ts
const now = () => Date.now();
var Nicks = class Nicks {
	static TTL = 6e4;
	map = /* @__PURE__ */ new Map();
	at = /* @__PURE__ */ new Map();
	pending = /* @__PURE__ */ new Map();
	set(uid, nickname) {
		this.map.set(uid, nickname);
		this.at.set(uid, now());
	}
	has(uid) {
		return this.map.has(uid);
	}
	/** TTL 过期视为未命中：昵称会变更，避免长期陈旧 */
	get(uid) {
		if (!this.map.has(uid)) return void 0;
		return now() - (this.at.get(uid) ?? 0) < Nicks.TTL ? this.map.get(uid) : void 0;
	}
	remember(entries) {
		for (const entry of entries) {
			const nickname = entry.alias ?? entry.nickname;
			if (nickname) this.set(entry.uid, nickname);
		}
	}
	/** 同一 uid 并发补拉只发一次请求，失败静默由下一条消息重试 */
	async once(uid, load) {
		const pending = this.pending.get(uid);
		if (pending) return pending;
		const task = load().catch(() => void 0).finally(() => {
			this.pending.delete(uid);
		});
		this.pending.set(uid, task);
		return task;
	}
};
//#endregion
//#region src/message/value.ts
/** 收侧 JSON 字段既可能是对象也可能缺省，取值统一在此收敛 */
function objectValue(value) {
	return value && typeof value === "object" && !Array.isArray(value) ? value : void 0;
}
function stringArray$1(value) {
	return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}
//#endregion
//#region src/message/body.ts
function audio(value, text) {
	const resource = objectValue(value["resource_url"]);
	return {
		type: "audio",
		text,
		audio: {
			urls: stringArray$1(resource?.["url_list"]),
			uri: String(resource?.["uri"] ?? "")
		}
	};
}
function file(value) {
	return {
		type: "file",
		text: String(value["name"] ?? ""),
		file: {
			uri: String(value["uri"] ?? ""),
			skey: String(value["skey"] ?? ""),
			md5: String(value["md5"] ?? ""),
			name: String(value["name"] ?? ""),
			dataSize: Number(value["data_size"] ?? 0)
		}
	};
}
/** 通话状态/一起看邀请：hint 即展示文本 */
function hint(value) {
	return {
		type: "text",
		text: String(value["hint"] ?? "")
	};
}
/** 系统引导模板（如开启消息通知）：无内容价值，置空文本由分发层过滤 */
function guide(value) {
	return Number(value["aweType"] ?? value["awe_type"] ?? 0) === 133 ? {
		type: "text",
		text: ""
	} : void 0;
}
function link(value) {
	return {
		type: "link",
		text: String(value["title"] ?? ""),
		link: {
			url: String(value["link_url"] ?? ""),
			title: String(value["title"] ?? ""),
			description: String(value["desc"] ?? ""),
			coverUrl: String(value["cover_url"] ?? "")
		}
	};
}
function userCard(value) {
	const coverArr = value["cover_url"];
	return {
		type: "userCard",
		text: String(value["name"] ?? ""),
		user: {
			uid: String(value["uid"] ?? ""),
			secUid: String(value["secUID"] ?? ""),
			name: String(value["name"] ?? ""),
			avatarUrl: stringArray$1(objectValue(value["avatar"])?.["url_list"])[0] ?? "",
			...value["desc"] !== void 0 && value["desc"] !== "" ? { desc: String(value["desc"]) } : {},
			...value["follower_count"] !== void 0 ? { followerCount: String(value["follower_count"]) } : {},
			...Array.isArray(value["cover_items"]) && value["cover_items"].length ? { coverItems: stringArray$1(value["cover_items"]) } : {},
			...Array.isArray(coverArr) && coverArr.length ? { coverUrls: coverArr.map((c) => stringArray$1(c.url_list)?.[0] ?? "").filter(Boolean) } : {}
		}
	};
}
/** 作品分享（messageType=8/77，或类型缺省时按 aweType=800 判定） */
function shareOf(value, text) {
	const title = String(value["content_title"] ?? "");
	const cover = objectValue(value["cover_url"]);
	const coverUrl = cover ? stringArray$1(cover["url_list"])[0] ?? String(cover["uri"] ?? "") : "";
	return {
		type: "share",
		text: text || title,
		share: {
			itemId: String(value["itemId"] ?? ""),
			title,
			uid: String(value["uid"] ?? ""),
			...value["secUID"] ? { secUid: String(value["secUID"]) } : {},
			...value["content_name"] ? { authorName: String(value["content_name"]) } : {},
			...coverUrl ? { coverUrl } : {}
		}
	};
}
function forward(value) {
	const summary = Array.isArray(value["list_content"]) ? value["list_content"] : [];
	const refs = Array.isArray(value["msg_ids"]) ? value["msg_ids"] : [];
	const refById = new Map(refs.map((ref) => [String(ref?.["msg_id"] ?? ""), ref]));
	const nodes = [];
	for (const item of summary) {
		const msgId = String(item?.["msgid"] ?? "");
		const ref = refById.get(msgId);
		nodes.push({
			uid: String(ref?.["uid"] ?? ""),
			nickname: String(item?.["nick_name"] ?? ""),
			text: String(item?.["text"] ?? ""),
			msgType: Number(ref?.["msg_type"] ?? 0),
			aweType: Number(ref?.["awe_type"] ?? 0),
			msgId,
			...ref?.["sec_uid"] ? { secUid: String(ref["sec_uid"]) } : {},
			...ref?.["create_time"] ? { createTime: Number(ref["create_time"]) } : {}
		});
	}
	return {
		type: "forward",
		text: "",
		nodes
	};
}
/** 接龙（群内多人接力登记项）：push_detail 即官方展示文本，describe 为标题 */
function chains(value) {
	const items = Array.isArray(value["chains_entry_list"]) ? value["chains_entry_list"] : [];
	return {
		type: "chains",
		text: String(value["push_detail"] ?? value["chains_description"] ?? ""),
		chains: {
			id: String(value["chains_id"] ?? ""),
			description: String(value["chains_description"] ?? ""),
			isStart: Number(value["is_start_chains"]) === 1,
			entries: items.map((item) => {
				const it = item;
				return {
					uid: String(it["e_c_u"] ?? ""),
					text: String(it["e_t"] ?? "")
				};
			})
		}
	};
}
/** 互动卡（messageType=110）：im_dynamic_patch 为卡片载荷，raw_data 是双层转义 JSON，description(=push_detail) 即展示文本。引导卡(aweType=110402/msg_guide)与打卡卡(110372/msg_preview)的 raw_data 布局不同，平铺字段各取首段候选回退 */
function card(value) {
	const patch = objectValue(value["im_dynamic_patch"]);
	const raw = typeof patch?.["raw_data"] === "string" ? objectValue(JSON.parse(patch["raw_data"])) : void 0;
	const pick = (...names) => {
		for (const name of names) {
			const cell = objectValue(raw?.[name])?.["content"];
			const hit = Array.isArray(cell) ? cell[0] : cell;
			if (typeof hit === "string" && hit) return hit;
		}
		return "";
	};
	let cardId = String(patch?.["card_id"] ?? "");
	if (!cardId && typeof patch?.["id"] === "string") {
		const nested = objectValue(JSON.parse(patch["id"]));
		cardId = String(nested?.["id"] ?? "");
	}
	return {
		type: "card",
		text: String(value["description"] ?? value["push_detail"] ?? ""),
		card: {
			key: String(patch?.["card_key"] ?? ""),
			type: String(patch?.["card_type"] ?? ""),
			id: cardId,
			aweType: Number(value["aweType"] ?? 0),
			title: pick("content_middle_top", "content_top"),
			desc: pick("content_middle_content", "content_middle"),
			button: pick("bottom", "bottom_right"),
			coverUrl: pick("content_left", "content_bottom"),
			sign: String(patch?.["sign"] ?? ""),
			patch: patch ?? {}
		}
	};
}
/** 位置消息（messageType=502，POI 定位）：坐标 + 地点名/地址，封面为 cover_info.resource_url */
function location(value) {
	const cover = objectValue(objectValue(value["cover_info"])?.["resource_url"]);
	return {
		type: "location",
		text: String(value["poi_name"] ?? value["poi_address"] ?? ""),
		location: {
			name: String(value["poi_name"] ?? ""),
			address: String(value["poi_address"] ?? ""),
			latitude: Number(value["latitude"] ?? 0),
			longitude: Number(value["longitude"] ?? 0),
			poiId: String(value["poi_id"] ?? ""),
			awemePoiId: String(value["aweme_poi_id"] ?? ""),
			uri: String(cover?.["uri"] ?? ""),
			urlList: stringArray$1(cover?.["url_list"])
		}
	};
}
/** 群聊邀请卡（messageType=58）：aweme_invite_card 为载荷，title 即展示文本 */
function groupCard(value) {
	const card = objectValue(value["aweme_invite_card"]);
	const icon = objectValue(card?.["group_icon"]);
	return {
		type: "groupCard",
		text: String(value["title"] ?? value["push_detail"] ?? ""),
		groupCard: {
			conversationId: String(card?.["conversation_id"] ?? ""),
			groupName: String(card?.["group_name"] ?? ""),
			iconUrl: stringArray$1(icon?.["url_list"])[0] ?? "",
			...card?.["group_member_count"] !== void 0 ? { memberCount: Number(card["group_member_count"]) } : {},
			...card?.["group_owner_uid"] ? { ownerUid: String(card["group_owner_uid"]) } : {},
			...card?.["sec_group_owner_uid"] ? { ownerSecUid: String(card["sec_group_owner_uid"]) } : {},
			...card?.["group_owner_nickname"] ? { ownerNickname: String(card["group_owner_nickname"]) } : {},
			fromUid: String(card?.["from_uid"] ?? ""),
			...card?.["sec_from_uid"] ? { fromSecUid: String(card["sec_from_uid"]) } : {},
			...card?.["ticket"] ? { ticket: String(card["ticket"]) } : {}
		}
	};
}
/** 群系统消息（messageType=1001）：文案在 locale_resources/template，渲染出可读文本而非丢给 unknown */
function system(value) {
	const text = systemMessageText(value);
	return text ? {
		type: "text",
		text
	} : void 0;
}
/** 系统消息占位用户（active_users/passive_users）：取昵称，缺昵称回退 uid */
function placeholderUsers(value) {
	if (!Array.isArray(value)) return [];
	const names = [];
	for (const item of value) {
		const record = objectValue(item);
		const name = String(record?.["nickname"] ?? record?.["nick_name"] ?? record?.["uid"] ?? "");
		if (name) names.push(name);
	}
	return names;
}
/**
* 群系统消息文案：服务端只下发模板，正文在 locale_resources（zh 优先）、回退 template，
* {0}/{1} 占位按 active_users→passive_users 顺序填昵称
*/
function systemMessageText(value) {
	const resources = (Array.isArray(value["locale_resources"]) ? value["locale_resources"] : []).map(objectValue).filter((item) => item !== void 0);
	const localized = (resources.find((item) => String(item["lang"] ?? "").startsWith("zh")) ?? resources[0])?.["text"];
	const template = typeof localized === "string" && localized ? localized : typeof value["template"] === "string" ? value["template"] : "";
	if (!template) return "";
	const users = [...placeholderUsers(value["active_users"]), ...placeholderUsers(value["passive_users"])];
	return template.replace(/\{(\d+)\}/g, (slot, index) => users[Number(index)] ?? slot);
}
const parsers = /* @__PURE__ */ new Map([
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
	[1001, system]
]);
//#endregion
//#region src/message/parse.ts
/** 类型缺省时按通用资源字段推断的消息类型（其余类型一律 unknown，避免误判） */
const generic = /* @__PURE__ */ new Set([
	1,
	2,
	5,
	7,
	27,
	30
]);
function imageFromObject(value) {
	const resource = objectValue(value["resource_url"]) ?? value;
	const oid = String(resource["oid"] ?? resource["uri"] ?? "");
	const skey = String(resource["skey"] ?? "");
	const urls = (name) => stringArray$1(resource[name] ?? value[name]);
	if (!oid && !skey && ![
		"origin_url_list",
		"large_url_list",
		"medium_url_list",
		"thumb_url_list"
	].some((name) => urls(name).some(Boolean))) return void 0;
	return {
		oid,
		skey,
		md5: String(resource["md5"] ?? value["md5"] ?? ""),
		dataSize: Number(resource["data_size"] ?? value["data_size"] ?? 0),
		width: Number(value["cover_width"] ?? resource["width"] ?? 0),
		height: Number(value["cover_height"] ?? resource["height"] ?? 0),
		originUrls: urls("origin_url_list"),
		largeUrls: urls("large_url_list"),
		mediumUrls: urls("medium_url_list"),
		thumbUrls: urls("thumb_url_list")
	};
}
/** 收侧 @ 提及：仅 infoType=1（@ 人）计入，位置/长度用于从原 text 剥离 */
function mentionsFromValue(value) {
	const infos = value["richTextInfos"];
	if (!Array.isArray(infos) || infos.length === 0) return void 0;
	const mentions = infos.map((item) => {
		const record = objectValue(item);
		if (!record || Number(record["infoType"]) !== 1) return void 0;
		const info = objectValue(record["info"]);
		return {
			uid: String(info?.["uid"] ?? ""),
			location: Number(record["location"] ?? 0),
			length: Number(record["length"] ?? 0)
		};
	}).filter((m) => m !== void 0 && m.uid !== "");
	return mentions.length ? mentions : void 0;
}
/** 按 location/length 从原文本剥离 @ 片段；从后往前裁避免偏移 */
function stripMentions(text, mentions) {
	const parts = [...mentions].sort((a, b) => b.location - a.location);
	let rest = text;
	for (const m of parts) {
		if (m.location < 0 || m.location + m.length > rest.length) continue;
		rest = rest.slice(0, m.location) + rest.slice(m.location + m.length);
	}
	return rest;
}
function videoFromObject(value, text) {
	const videoValue = objectValue(value["video"]);
	const posterValue = objectValue(value["poster"]);
	const poster = posterValue ? imageFromObject(posterValue) : void 0;
	return {
		type: "video",
		text,
		video: {
			tkey: String(videoValue["tkey"] ?? ""),
			skey: String(videoValue["skey"] ?? ""),
			md5: String(videoValue["md5"] ?? ""),
			width: Number(value["width"] ?? 0),
			height: Number(value["height"] ?? 0),
			checkPics: stringArray$1(value["check_pics"]),
			...poster ? { poster } : {},
			...value["inline_pic"] ? { inlinePic: String(value["inline_pic"]) } : {}
		}
	};
}
/**
* 解析 wire content 为收侧消息体（RecvBody）：type 判别 + 载荷字段平铺，媒体恒为资产/资源形态。
* text 为可读展示文本（媒体字段无文案时保持原值，不再内填「[视频]」等占位，
* 拼接展示交由外部按 type 处理，避免外部再追加时重复）；@ 提及并入 text 的 ats（纯 @ 消息 text 保留原文）。
*/
function parseBody(content, messageType) {
	let value;
	try {
		const decoded = JSON.parse(content.replace(/"(\w+)"\s*:\s*(\d{16,})/g, "\"$1\":\"$2\""));
		if (!objectValue(decoded)) return {
			type: "unknown",
			text: content,
			raw: content
		};
		value = decoded;
	} catch {
		return {
			type: "text",
			text: content
		};
	}
	const aweType = Number(value["aweType"] ?? value["awe_type"] ?? 0);
	const text = String(value["text"] ?? value["content"] ?? value["display_name"] ?? "");
	const typed = messageType == null ? void 0 : parsers.get(messageType)?.(value, text);
	if (typed) return typed;
	if (messageType == null && aweType === 800) return shareOf(value, text);
	if (messageType != null && !generic.has(messageType)) return {
		type: "unknown",
		text,
		raw: value
	};
	const image = imageFromObject(value);
	if (image) return {
		type: "image",
		text,
		image
	};
	if (objectValue(value["video"])) return videoFromObject(value, text);
	const emojiUrl = objectValue(value["url"]);
	const url = String(emojiUrl?.["uri"] ?? stringArray$1(emojiUrl?.["url_list"])[0] ?? "");
	if (aweType === 507 || url) return {
		type: "emoji",
		text,
		emoji: url
	};
	if (text || "text" in value) {
		const mentions = mentionsFromValue(value);
		if (!mentions) return {
			type: "text",
			text
		};
		const stripped = stripMentions(text, mentions);
		const ats = mentions.sort((a, b) => a.location - b.location).map((m) => ({ uid: m.uid }));
		return {
			type: "text",
			text: stripped || text,
			ats
		};
	}
	return {
		type: "unknown",
		text,
		raw: value
	};
}
//#endregion
//#region src/notice/field.ts
/** 无 schema wire 辅助（等价 android-ws.ts 的提取 helpers，通知与推送共用） */
function fieldString(fields, number) {
	for (const field of fields) {
		if (field.field === number && field.type === "varint") return field.value.toString();
		if (field.field === number && field.type === "string") return field.value;
	}
}
function messageChildren(fields, number) {
	return fields.filter((field) => field.field === number && field.type === "message").map((field) => field.value);
}
/** 还原客户端 fixed64 打包的短键：f1 嵌套 message 的子字段字节顺序拼成 ASCII（如 :group_co 补全） */
function keyFromNested(fields, number) {
	const nested = fields.find((field) => field.field === number && field.type === "message")?.value;
	if (!nested?.length) return void 0;
	const parts = [];
	for (const field of nested) if (field.type === "fixed64" || field.type === "fixed32") parts.push(Buffer.from(field.value));
	else if (field.type === "varint") parts.push(encodeVarint(field.value));
	return Buffer.concat(parts).toString("utf8") || void 0;
}
function collectKeyValues(fields, number) {
	const values = /* @__PURE__ */ new Map();
	for (const child of messageChildren(fields, number)) {
		const key = fieldString(child, 1) ?? keyFromNested(child, 1);
		const value = fieldString(child, 2);
		if (key && value != null) values.set(key, value);
	}
	return values;
}
/** 16+ 位整数（uid/conversation_id）超出 Number 精度，包成字符串再 parse；
* 覆盖对象键值、数组元素与首元素，字符串内的数字（已带引号）不重复包装 */
function protectBigInt(text) {
	return text.replace(/(?<![\d"])(\d{16,})(?![\d"])/g, "\"$1\"");
}
function asRecord$1(value) {
	return typeof value === "object" && value !== null ? value : void 0;
}
function firstString(record, keys) {
	for (const key of keys) {
		const value = record?.[key];
		if (typeof value === "string" || typeof value === "number" || typeof value === "bigint") {
			const text = String(value);
			if (text && text !== "0") return text;
		}
	}
}
/** 命令帧 content 解析：非法或非对象一律 undefined，由调用方按缺省处理 */
function commandPayload(content) {
	try {
		return asRecord$1(JSON.parse(protectBigInt(content)));
	} catch {
		return;
	}
}
function noticeUsers(value) {
	if (!Array.isArray(value)) return [];
	const users = [];
	for (const item of value) {
		const user = asRecord$1(item);
		const uid = firstString(user, [
			"uid",
			"user_id",
			"userId"
		]);
		if (!uid) continue;
		const secUid = firstString(user, [
			"sec_uid",
			"secUid",
			"sec_user_id",
			"secUserId"
		]);
		const nickname = firstString(user, [
			"nickname",
			"nick_name",
			"display_name",
			"displayName"
		]);
		users.push({
			uid,
			...secUid ? { secUid } : {},
			...nickname ? { nickname } : {}
		});
	}
	return users;
}
//#endregion
//#region src/notice/frame.ts
/** Android Frontier 原生通知/请求事件（501 已读、502 会话更新、507 好友事件、504 输入状态） */
function extractAndroidNotices(payload) {
	const top = decodeWire(payload);
	const tree = decodeWireTree(payload);
	const envelopes = messageChildren(top, 8);
	if (messageChildren(top, 6).length > 0) envelopes.push(top);
	const notices = [];
	for (const envelope of envelopes) for (const body of messageChildren(envelope, 6)) {
		for (const read of messageChildren(body, 501)) notices.push({
			type: "conversation.read",
			conversationId: fieldString(read, 1) ?? "",
			conversationType: Number(fieldString(read, 2) ?? 0),
			readMessageIndex: fieldString(read, 3) ?? "0",
			readMessageIndexV2: fieldString(read, 4) ?? "0",
			raw: {
				transport: "android-frontier",
				wireTree: tree
			}
		});
		for (const updated of messageChildren(body, 502)) for (const conversation of messageChildren(updated, 1)) notices.push({
			type: "conversation.update",
			conversationId: fieldString(conversation, 1) ?? "",
			conversationType: Number(fieldString(conversation, 3) ?? 0),
			raw: {
				transport: "android-frontier",
				wireTree: tree
			}
		});
		for (const friend of messageChildren(body, 507)) {
			const messageType = Number(fieldString(friend, 1) ?? 0);
			const fromUid = fieldString(friend, 2) ?? "";
			const toUid = fieldString(friend, 3) ?? "";
			const peerUid = fromUid || toUid;
			const content = fieldString(friend, 4);
			if (messageType === 1 && peerUid) notices.push({
				type: "friend.request",
				applicantUid: peerUid,
				...fromUid ? { fromUid } : {},
				...toUid ? { toUid } : {},
				...content ? { content } : {},
				raw: {
					transport: "android-frontier",
					wireTree: tree
				}
			});
			else if ((messageType === 2 || messageType === 3) && peerUid) notices.push({
				type: messageType === 3 ? "friend.increase" : "friend.decrease",
				peerUid,
				...fromUid ? { fromUid } : {},
				...toUid ? { toUid } : {},
				...content ? { content } : {},
				raw: {
					transport: "android-frontier",
					wireTree: tree
				}
			});
		}
		for (const typing of messageChildren(body, 504)) {
			const content = commandPayload(fieldString(typing, 8) ?? "");
			const inputStatus = Number(content?.["input_status"] ?? -1);
			if (inputStatus < 0) continue;
			const conversationId = fieldString(typing, 4) ?? "";
			const peerUid = fieldString(typing, 2) ?? "";
			const senderUid = fieldString(typing, 22) ?? peerUid;
			if (!conversationId && !peerUid) continue;
			const peerSecUid = fieldString(typing, 3);
			notices.push({
				type: "conversation.typing",
				conversationId,
				peerUid,
				...peerSecUid ? { peerSecUid } : {},
				senderUid,
				typing: inputStatus === 1,
				raw: {
					transport: "android-frontier",
					wireTree: tree
				}
			});
		}
	}
	return notices;
}
//#endregion
//#region src/notice/notice.ts
const commandTypes = /* @__PURE__ */ new Set([
	40001,
	50001,
	50002,
	50003,
	50004,
	50005,
	50010,
	50011,
	50012,
	50013,
	50014,
	50015,
	50016,
	50017,
	60001,
	70001,
	70002,
	80001,
	80002,
	80003,
	80004,
	80005,
	90001,
	90002
]);
const increaseTypes = /* @__PURE__ */ new Map([
	[100100, "invite"],
	[100101, "command"],
	[100102, "qrcode"],
	[100107, "duoshan"],
	[100109, "apply"],
	[100111, "search"],
	[100112, "activity"],
	[100113, "face-to-face"],
	[100114, "circle"],
	[100128, "qrcode"],
	[100140, "invite"]
]);
const decreaseTypes = /* @__PURE__ */ new Map([[100104, "kick"], [100105, "leave"]]);
function aweTypeOf(payload) {
	return Number(payload["aweType"] ?? payload["awe_type"] ?? 0);
}
function groupMemberIncrease(push, payload) {
	if (push.conversationType !== 2 || !payload) return void 0;
	const source = increaseTypes.get(aweTypeOf(payload));
	if (!source) return void 0;
	const members = noticeUsers(payload["passive_users"] ?? payload["passiveUsers"]);
	if (members.length === 0) return void 0;
	return {
		type: "group.member-increase",
		conversationId: push.conversationId,
		conversationShortId: push.conversationShortId || push.conversationId,
		conversationType: 2,
		source,
		members,
		operators: noticeUsers(payload["active_users"] ?? payload["activeUsers"]),
		raw: push.raw
	};
}
function groupMemberDecrease(push, payload) {
	if (push.conversationType !== 2 || !payload) return void 0;
	const source = decreaseTypes.get(aweTypeOf(payload));
	if (!source) return void 0;
	const activeUsers = noticeUsers(payload["active_users"] ?? payload["activeUsers"]);
	const passiveUsers = noticeUsers(payload["passive_users"] ?? payload["passiveUsers"]);
	const members = source === "leave" ? activeUsers : passiveUsers;
	if (members.length === 0) return void 0;
	return {
		type: "group.member-decrease",
		conversationId: push.conversationId,
		conversationShortId: push.conversationShortId || push.conversationId,
		conversationType: 2,
		source,
		members,
		operators: source === "leave" ? [] : activeUsers,
		raw: push.raw
	};
}
/** 群名/头像/管理员/解散：aweType 决定语义，载荷字段同源 */
function groupMeta(push, payload) {
	if (push.conversationType !== 2 || !payload) return void 0;
	const aweType = aweTypeOf(payload);
	const base = {
		conversationId: push.conversationId,
		conversationShortId: push.conversationShortId || push.conversationId,
		conversationType: 2,
		operators: noticeUsers(payload["active_users"] ?? payload["activeUsers"]),
		raw: push.raw
	};
	if (aweType === 100110) {
		const members = noticeUsers(payload["passive_users"] ?? payload["passiveUsers"]);
		if (members.length === 0) return void 0;
		return {
			type: "group.admin",
			...base,
			members,
			enabled: true
		};
	}
	if (aweType === 100106) {
		const name = firstString(payload, [
			"new_name",
			"newName",
			"conversation_name",
			"conversationName",
			"name"
		]);
		return {
			type: "group.name-change",
			...base,
			...name ? { name } : {}
		};
	}
	if (aweType === 100115) {
		const avatar = firstString(payload, [
			"new_avatar",
			"newAvatar",
			"avatar_url",
			"avatarUrl",
			"avatar"
		]);
		return {
			type: "group.avatar-change",
			...base,
			...avatar ? { avatar } : {}
		};
	}
	if (aweType === 100124) {
		const uid = push.senderUid || noticeUsers(payload["active_users"])?.[0]?.uid;
		return {
			type: "group.dismiss",
			...base,
			...uid ? {
				operatorUid: uid,
				operators: [{ uid }]
			} : {}
		};
	}
}
/** messageType=50011 群成员进出 diff（block_status 1=被移出/0=加入）；与 aweType 系统消息双通道并存 */
function groupMemberDiff(push) {
	if (push.conversationType !== 2) return void 0;
	const payload = commandPayload(push.content);
	const blockStatus = Number(payload?.["block_status"]);
	if (blockStatus !== 0 && blockStatus !== 1) return void 0;
	const members = [];
	for (const item of Array.isArray(payload?.["updated_participant_info"]) ? payload?.["updated_participant_info"] : []) {
		const it = asRecord$1(item);
		if (!it || Number(it["blocked"] ?? -1) !== blockStatus) continue;
		const uid = firstString(it, [
			"user_id",
			"uid",
			"userId"
		]);
		if (!uid) continue;
		const secUid = firstString(it, ["sec_uid", "secUid"]);
		members.push({
			uid,
			...secUid ? { secUid } : {}
		});
	}
	if (members.length === 0) for (const uid of Array.isArray(payload?.["userID"]) ? payload["userID"] : []) {
		const text = uid == null ? "" : String(uid);
		if (text) members.push({ uid: text });
	}
	if (members.length === 0) return void 0;
	const operators = push.senderUid ? [{ uid: push.senderUid }] : [];
	const base = {
		conversationId: push.conversationId,
		conversationShortId: push.conversationShortId || push.conversationId,
		conversationType: 2,
		members,
		operators,
		raw: push.raw
	};
	return blockStatus === 1 ? {
		type: "group.member-decrease",
		...base,
		source: "kick"
	} : {
		type: "group.member-increase",
		...base,
		source: "rejoin"
	};
}
/** 把 cmd500 中的协议命令消息与用户可见消息分流为 Notice 或 Request。 */
function noticeFromPush(push) {
	const payload = commandPayload(push.content);
	const group = groupMemberIncrease(push, payload) ?? groupMemberDecrease(push, payload) ?? groupMeta(push, payload);
	if (group) return group;
	if (!commandTypes.has(push.messageType)) return void 0;
	if (push.messageType === 50011) {
		const diff = groupMemberDiff(push);
		if (diff) return diff;
	}
	if (push.messageType === 40001) {
		const serverMessageId = push.ext?.["s:target_server_message_id"];
		const targetClientMessageId = push.ext?.["s:target_client_message_id"];
		const recallUid = push.ext?.["s:recall_uid"];
		const recallRole = push.ext?.["s:recall_role"];
		return {
			type: "message.recall",
			conversationId: push.conversationId,
			conversationType: push.conversationType,
			...serverMessageId ? { serverMessageId } : {},
			...targetClientMessageId ? { targetClientMessageId } : {},
			...recallUid ? { recallUid } : {},
			...recallRole ? { recallRole: Number(recallRole) } : {},
			...push.ext ? { ext: push.ext } : {},
			raw: push.raw
		};
	}
	if (push.messageType === 50005) return {
		type: "conversation.delete",
		conversationId: push.conversationId,
		conversationType: push.conversationType,
		...push.ext ? { ext: push.ext } : {},
		raw: push.raw
	};
	if (push.messageType === 90001) {
		const apply = asRecord$1(payload?.["apply_info"] ?? payload?.["applyInfo"]);
		const groupShortId = firstString(apply ?? payload, [
			"conv_short_id",
			"convShortId",
			"conversation_short_id",
			"conversationShortId"
		]);
		const requestId = firstString(apply ?? payload, [
			"apply_id",
			"applyId",
			"request_id",
			"requestId"
		]);
		return {
			type: "group.join-request",
			conversationId: push.conversationId,
			conversationShortId: groupShortId || push.conversationShortId || push.conversationId,
			conversationType: push.conversationType,
			...requestId ? { requestId } : {},
			content: push.content,
			raw: push.raw
		};
	}
	return {
		type: "im.command",
		conversationId: push.conversationId,
		conversationType: push.conversationType,
		messageType: push.messageType,
		content: push.content,
		raw: push.raw
	};
}
//#endregion
//#region src/message/json.ts
/** 推送 content 偶发非 JSON 变体，解析失败交给调用方按缺省处理；protect 时保 16+ 位数字精度 */
function parseContent(text, protect = false) {
	try {
		return JSON.parse(protect ? protectBigInt(text) : text);
	} catch {
		return;
	}
}
const str$2 = (value) => value == null ? "" : String(value);
const num = (value) => value == null ? 0 : Number(value);
//#endregion
//#region src/message/push.ts
/** content 恒为空、信息全在 ext 的命令帧类型（50005 会话删除/群解散，实证帧 content 为空） */
const bodyless = new Set(cmd.bodyless);
/**
* 无 schema 提取嵌套引用信息（对齐实际帧形态）：
* field 1 = referencedMessageId（int64 → varint），field 2 = hint JSON（含 refmsg_type/refmsg_uid 等键），
* field 3 = refmsg_type（公告/系统消息等无本地上下文），field 8/9 = 被引消息索引。
* 引用的是无上下文消息（如群公告 refmsg_type=1004）时只透出 replyid，不编造 rootMessageId。
*/
function extractReference(fields) {
	for (const field of fields) {
		if (field.type !== "message") continue;
		const hint = field.value.find((item) => item.type === "string" && item.value.includes("refmsg_type"))?.value;
		if (!hint) continue;
		const refId = field.value.find((item) => item.type === "varint" && item.field === 1)?.value;
		if (refId === void 0) continue;
		return {
			referencedMessageId: refId.toString(),
			hint
		};
	}
}
function collectMessages(fields, output, rawTree, inherited = {}) {
	const strings = fields.filter((item) => item.type === "string").map((item) => ({
		field: item.field,
		value: item.value
	}));
	const context = { ...inherited };
	const envelopeCmd = fieldString(fields, 1);
	const envelopeInboxType = fieldString(fields, 5);
	if (envelopeCmd && envelopeInboxType && (envelopeInboxType === "0" || envelopeInboxType === "1")) {
		context.cmd = Number(envelopeCmd);
		context.inboxType = Number(envelopeInboxType);
	}
	const conversationId = strings.find(({ value }) => /^0:1:\d+:\d+$/.test(value))?.value ?? strings.find(({ field, value }) => field === 1 && /^\d+$/.test(value))?.value;
	if (conversationId) context.conversationId = conversationId;
	const signalHead = fieldString(fields, 7);
	const signalLayout = !!signalHead && /^\d{5}$/.test(signalHead);
	const senderUid = fieldString(fields, signalLayout ? 22 : 7);
	if (senderUid && senderUid.length >= 15 && /^\d+$/.test(senderUid)) context.senderUid = senderUid;
	const senderSecUid = fieldString(fields, 14);
	if (senderSecUid?.startsWith("MS4")) context.senderSecUid = senderSecUid;
	const directThreadId = strings.find(({ value }) => /^\d+:[0-9a-fA-F-]+-[0-9a-fA-F]+:\d+$/.test(value))?.value;
	const threadExt = collectKeyValues(fields, 9);
	const addExt = parseContent(threadExt.get("s:add_ext") ?? "");
	const addThreadId = str$2(addExt?.["a:thread_id"]);
	if (directThreadId) context.threadId = directThreadId;
	if (addThreadId) context.threadId = addThreadId;
	const editRaw = parseContent(threadExt.get("s:edit_info") ?? "", true);
	const editCount = threadExt.get("s:edit_count");
	if (editRaw?.["content_is_edited"] === true || editCount && Number(editCount) > 0) {
		context.editCount = editCount ? Number(editCount) : 1;
		context.editInfo = {
			contentIsEdited: editRaw?.["content_is_edited"] === true,
			editorUid: str$2(editRaw?.["content_editor"]),
			editTime: str$2(editRaw?.["content_edit_time"])
		};
		const orgType = threadExt.get("s:org_msg_type");
		if (orgType && /^\d+$/.test(orgType)) context.orgMsgType = Number(orgType);
	}
	const shortId = fieldString(fields, 5);
	if (!directThreadId && (conversationId || senderUid) && shortId && /^\d+$/.test(shortId)) context.conversationShortId = shortId;
	if (context.threadId) {
		const extServerId = threadExt.get("s:server_message_id");
		context.threadShortId = str$2(addExt?.["a:thread_short_id"]) || (directThreadId && shortId && /^\d+$/.test(shortId) ? shortId : void 0);
		context.isThreadRoot = addExt?.["a:is_thread_root_msg"] === "1";
		if (extServerId && /^\d+$/.test(extServerId)) context.serverMessageId = extServerId;
		if (!conversationId) {
			const tail = context.threadId.split(":")[2];
			if (tail && /^\d+$/.test(tail)) {
				context.conversationId = tail;
				context.conversationShortId = context.conversationShortId ?? tail;
			}
		}
	}
	const serverMessageId = fieldString(fields, 3);
	if ((conversationId || senderUid) && serverMessageId && /^\d+$/.test(serverMessageId)) context.serverMessageId = serverMessageId;
	const editServerId = threadExt.get("s:server_message_id");
	if (context.editCount != null && editServerId && /^\d+$/.test(editServerId)) context.serverMessageId = editServerId;
	const indexInConversation = fieldString(fields, 4);
	if ((conversationId || senderUid) && indexInConversation) context.indexInConversation = indexInConversation;
	const indexInConversationV2 = fieldString(fields, 17);
	if ((conversationId || senderUid) && indexInConversationV2) context.indexInConversationV2 = indexInConversationV2;
	const createTime = fieldString(fields, 10);
	if ((conversationId || senderUid) && createTime) context.createTime = createTime;
	const reference = extractReference(fields);
	if ((conversationId || senderUid) && reference) context.reference = reference;
	const contentField = fields.find((item) => item.type === "string" && (item.field === 8 || item.field === 6) && item.value.trimStart().startsWith("{"));
	const content = contentField?.value ?? "";
	const bodylessCommand = !contentField && threadExt.size > 0 && bodyless.has(Number(fieldString(fields, 6) ?? 7));
	if (context.conversationId && context.senderUid && (contentField || context.isThreadRoot || bodylessCommand)) output.push({
		cmd: context.cmd ?? 500,
		...context.inboxType !== void 0 ? { inboxType: context.inboxType } : {},
		conversationId: context.conversationId,
		conversationShortId: context.conversationShortId ?? "",
		conversationType: /^\d+$/.test(context.conversationId) ? 2 : 1,
		senderUid: context.senderUid,
		...context.senderSecUid ? { senderSecUid: context.senderSecUid } : {},
		content,
		messageType: signalLayout ? Number(signalHead) : Number(fieldString(fields, 6) ?? 7),
		...context.serverMessageId ? { serverMessageId: context.serverMessageId } : {},
		...context.indexInConversation ? { indexInConversation: context.indexInConversation } : {},
		...context.indexInConversationV2 ? { indexInConversationV2: context.indexInConversationV2 } : {},
		...context.createTime ? { createTime: context.createTime } : {},
		...context.reference ? { reference: context.reference } : {},
		...context.threadId ? { threadId: context.threadId } : {},
		...context.threadShortId ? { threadShortId: context.threadShortId } : {},
		...context.isThreadRoot ? { isThreadRoot: context.isThreadRoot } : {},
		...context.editCount != null ? { editCount: context.editCount } : {},
		...context.editInfo ? { editInfo: context.editInfo } : {},
		...context.orgMsgType != null ? { orgMsgType: context.orgMsgType } : {},
		...threadExt.size > 0 ? { ext: Object.fromEntries(threadExt) } : {},
		raw: {
			transport: "android-frontier",
			content,
			wireTree: rawTree
		}
	});
	for (const field of fields) if (field.type === "message") collectMessages(field.value, output, rawTree, context);
}
/** Android Frontier payload 的无 schema 消息提取 */
function extractAndroidPushes(payload) {
	const output = [];
	collectMessages(decodeWire(payload), output, decodeWireTree(payload));
	const unique = /* @__PURE__ */ new Map();
	for (const message of output) unique.set(`${message.serverMessageId ?? ""}|${message.conversationId}|${message.senderUid}|${message.content}`, message);
	return [...unique.values()];
}
//#endregion
//#region src/message/event.ts
/** messageType=50018 来电推送 → voip 事件；content 无 call_info（异常/非来电变体）返回 undefined */
function toVoipCall(push) {
	const parsed = parseContent(push.content);
	if (!parsed) return void 0;
	const call = parsed.call_info;
	if (!call) return void 0;
	return {
		type: "voip.call",
		conversationId: push.conversationId,
		conversationType: push.conversationType,
		callerUid: push.senderUid,
		callId: str$2(call.call_id),
		roomId: str$2(call.room_id),
		voipType: num(call.voip_type),
		callType: num(call.call_type),
		cameraOff: num(call.camera_off),
		callInfo: call
	};
}
/** messageType=50013 单聊已读回执 → read 事件；content 无 P2PSender（异常变体）返回 undefined */
function toReadEvent(push) {
	const info = parseContent(push.content);
	if (!info) return void 0;
	const readerUid = info.P2PSender;
	if (readerUid == null) return void 0;
	return {
		type: "read",
		conversationId: push.conversationId,
		readerUid: str$2(readerUid),
		conShortId: str$2(info.ConShortId),
		messageId: str$2(info.MessageId),
		readIndex: str$2(info.P2PSenderReadIndex)
	};
}
/** messageType=50001 会话状态变更 → status 事件；content 无 conversation_id（异常变体）返回 undefined */
function toStatusEvent(push) {
	const info = parseContent(push.content, true);
	if (!info) return void 0;
	const conversationId = info.conversation_id;
	if (conversationId == null) return void 0;
	const extData = Array.isArray(info.ext_data) ? statusExt(info.ext_data) : void 0;
	const memberDiff = num(info.command_type) === 7 ? memberChange(info) : void 0;
	return {
		type: "status",
		conversationId: str$2(conversationId),
		conversationType: num(info.conversation_type),
		commandType: num(info.command_type),
		...info.read_badge_count != null ? { unread: num(info.read_badge_count) } : {},
		readIndex: str$2(info.read_index),
		...push.serverMessageId ? { messageId: push.serverMessageId } : {},
		...num(info.command_type) === 6 ? convChange(info, extData) : {},
		...memberDiff ? { memberChange: memberDiff } : {},
		...extData ? { extData } : {},
		raw: info
	};
}
/** command_type=6 帧 → 群名/群头像变更；改名帧也带头像键，按 ext_data 变更键优先定夺，故改名判定在头像之前 */
function convChange(info, extData) {
	const hit = (key) => extData?.find((item) => item.key === key);
	const nameOp = hit("a:s_name_operator");
	const lifecycle = hit("a:group_name_lifecycle");
	if (nameOp || lifecycle && lifecycle.value.includes("name_change")) return { nameChange: {
		name: str$2(info.conversation_name),
		operatorUid: nameOp ? nameOp.value : ""
	} };
	const avatarOp = hit("a:group_avatar_user_set") ?? hit("s_user_set_avatar");
	const avatarUrl = hit("a:ab_avatar");
	if (avatarOp || avatarUrl) return { avatarChange: {
		icon: str$2(info.conversation_icon) || (avatarUrl ? avatarUrl.value : ""),
		operatorUid: avatarOp ? avatarOp.value : ""
	} };
	return {};
}
/** command_type=7 帧 → 群成员变更（增删成员/角色/群主/群昵称变更）；无任何变化返回 undefined */
function memberChange(info) {
	const updated = (Array.isArray(info.updated_participant_info) ? info.updated_participant_info : []).map((item) => {
		const it = item;
		return {
			uid: str$2(it.user_id),
			role: num(it.role),
			...it.sec_uid ? { secUid: str$2(it.sec_uid) } : {},
			...typeof it.alias === "string" ? { alias: it.alias } : {}
		};
	}).filter((u) => u.uid !== "");
	const added = stringArray(info.added_participant);
	const removed = stringArray(info.removed_participant);
	if (added.length === 0 && removed.length === 0 && updated.length === 0) return void 0;
	const oldOwnerId = str$2(info.old_owner_id);
	const newOwnerId = str$2(info.new_owner_id);
	const transfer = newOwnerId !== "" && newOwnerId !== "0";
	return {
		added,
		removed,
		updated,
		...transfer && oldOwnerId !== "" && oldOwnerId !== "0" ? { oldOwnerId } : {},
		...transfer ? { newOwnerId } : {}
	};
}
function stringArray(value) {
	return Array.isArray(value) ? value.map((v) => v == null ? "" : String(v)).filter((v) => v !== "") : [];
}
/** content.ext_data → 会话属性变更项（key/value/version/op_type） */
function statusExt(items) {
	return items.map((item) => {
		const it = item;
		return {
			key: str$2(it.key),
			value: str$2(it.value),
			version: num(it.version),
			opType: num(it.op_type)
		};
	});
}
/** varint 字段值（bigint → string） */
function fieldVarint(fields, field) {
	return (fields.find((item) => item.type === "varint" && item.field === field)?.value)?.toString();
}
/**
* cmd=500 field=500 property 推送 → 消息表情回应（ModifyPropertyBody 同构下发）：
* f1=conversation_id, f2=conversation_type, f3=conversation_short_id, f4=server_message_id,
* f5=client_message_id, f6=repeated ModifyPropertyContent{operation=1,key=2,value=3,idempotent_id=4}
*/
function extractReactions(payload) {
	const events = [];
	const visit = (fields) => {
		for (const item of fields) {
			if (item.type === "message") visit(item.value);
			if (item.type !== "message" || item.field !== 500) continue;
			for (const body of item.value.filter((inner) => inner.type === "message" && inner.field === 5)) {
				const list = body.value;
				const conversationId = list.find((inner) => inner.type === "string" && inner.field === 1)?.value;
				const bigId = (field) => {
					const value = fieldVarint(list, field);
					return value && value.length >= 18 ? value : void 0;
				};
				const serverMessageId = bigId(4) ?? bigId(3);
				if (!conversationId || !serverMessageId) continue;
				for (const content of list.filter((inner) => inner.type === "message" && inner.field === 6)) {
					const inner = content.value;
					const operation = Number(fieldVarint(inner, 1) ?? "0");
					const rawKey = inner.find((el) => el.type === "string" && el.field === 2)?.value;
					const operatorUid = inner.find((el) => el.type === "string" && el.field === 4)?.value;
					if (!rawKey || !rawKey.includes(":")) continue;
					events.push({
						type: "message.reaction",
						conversationId,
						serverMessageId,
						emoji: rawKey.replace(/^se:/, ""),
						operatorUid: operatorUid ?? "",
						isSet: operation === 0,
						raw: {}
					});
				}
			}
		}
	};
	visit(decodeWire(payload));
	return events;
}
//#endregion
//#region src/message/recv.ts
/** 原始推送 → 业务入站消息（平铺消息体：type 判别 + text 展示文本） */
function toInboundMessage(push) {
	return {
		...parseBody(push.content, push.messageType),
		...push
	};
}
//#endregion
//#region src/bot/receive.ts
/** 实时接收：Android Frontier 长连接 + 推送分流（信号、编辑、通知、消息） */
/** 系统消息类型：常由本机触发，需先于自发过滤分流为 notice */
const NOTICE_TYPES$1 = /* @__PURE__ */ new Set([1001, 50011]);
var Receiver = class extends Emitter {
	ws;
	selfUid;
	selfMessage;
	/** 高位信令先于自发过滤：发送者常为本机，但语义是对端/会话视角 */
	signals = /* @__PURE__ */ new Map([
		[50001, (push) => {
			const e = toStatusEvent(push);
			if (e) this.emit("status", e);
		}],
		[50013, (push) => {
			const e = toReadEvent(push);
			if (e) this.emit("read", e);
		}],
		[50018, (push) => {
			const e = toVoipCall(push);
			if (e) this.emit("voip", e);
		}]
	]);
	constructor(opts) {
		super();
		this.selfUid = opts.userId;
		this.selfMessage = opts.selfMessage ?? false;
		this.ws = new AndroidFrontierWs({
			userId: opts.userId,
			cookies: opts.cookies,
			callbacks: {
				onMessage: (bytes) => this.frame(bytes),
				onReconnecting: (event) => this.emit("reconnecting", event),
				onClose: (event) => this.emit("close", event)
			}
		});
	}
	get connected() {
		return this.ws.connected;
	}
	async start() {
		if (this.ws.connected) return;
		await this.ws.connect();
	}
	stop() {
		this.ws.close();
	}
	/** 一帧内可能包含多类推送：先信号与通知，再普通消息 */
	frame(bytes) {
		for (const notice of extractAndroidNotices(bytes)) this.route(notice);
		for (const reaction of extractReactions(bytes)) this.emit("notice", reaction);
		for (const push of extractAndroidPushes(bytes)) this.dispatch(push);
	}
	dispatch(push) {
		const signal = this.signals.get(push.messageType);
		if (signal) {
			signal(push);
			return;
		}
		if (push.editCount != null || push.editInfo) {
			this.emit("message:edited", toInboundMessage(push));
			return;
		}
		if (NOTICE_TYPES$1.has(push.messageType)) {
			const event = noticeFromPush(push);
			if (event) {
				this.route(event);
				return;
			}
		}
		if (push.messageType >= 5e4 && !push.isThreadRoot) return;
		if (push.senderUid === this.selfUid && !this.selfMessage) return;
		const event = push.isThreadRoot ? void 0 : noticeFromPush(push);
		if (event) {
			this.route(event);
			return;
		}
		this.emit("message", toInboundMessage(push));
	}
	/** 好友申请/入群申请走 request，其余通知走 notice */
	route(event) {
		if (event.type === "friend.request" || event.type === "group.join-request") this.emit("request", event);
		else this.emit("notice", event);
	}
};
//#endregion
//#region src/media/source.ts
/** 输入是否是「待上传的源」；对象型输入已是资产，直接透传 */
const isInput = (v) => typeof v === "string" || v instanceof Uint8Array || v instanceof ArrayBuffer;
/**
* 只解析不识别：字节原样返回，字符串依次尝试读文件、抓 URL、按 base64 解码。
* 单一格式不认识时不提前判定，解析全部失败才把原始输入交回。
*/
async function resolveMedia(input) {
	if (input instanceof Uint8Array) return input;
	if (input instanceof ArrayBuffer) return new Uint8Array(input);
	try {
		return await readFile(input);
	} catch {}
	try {
		const res = await fetch(input);
		if (res.ok) return new Uint8Array(await res.arrayBuffer());
	} catch {}
	const raw = input.replace(/^base64:\/\//i, "").replace(/\s/g, "");
	const bytes = Buffer.from(raw, "base64");
	if (bytes.length > 0) return bytes;
	return err({ input });
}
/** 文件名只从路径/URL 尾部取；取不到就用调用方缺省值 */
function fileNameOf(input) {
	if (typeof input !== "string") return "file";
	return (input.split(/[?#]/)[0].split(/[\\/]/).pop() ?? "") || "file";
}
//#endregion
//#region src/media/video.ts
/** 视频本地处理：MP4 尺寸探测与首帧封面抽取（支撑无封面/无尺寸发送） */
/** 轻量尺寸探测：读 MP4 视频轨元数据（codedWidth/codedHeight），不解码（探测不到返回 0,0） */
async function probeVideo(data) {
	const demuxer = new Mp4Demuxer({ error: () => {} });
	try {
		await demuxer.loadBuffer(data);
		const track = demuxer.tracks.find((t) => t.trackType === "video");
		return {
			width: track?.codedWidth ?? 0,
			height: track?.codedHeight ?? 0
		};
	} catch {
		return {
			width: 0,
			height: 0
		};
	} finally {
		demuxer.close();
	}
}
/** 解码视频首帧为 JPEG 封面，顺带返回像素尺寸（无视频轨或无法解码时抛错） */
async function extractVideoPoster(data) {
	let first;
	let cause;
	const onError = (e) => {
		cause ??= e;
	};
	const decoder = new VideoDecoder({
		output: (frame) => {
			if (first) {
				frame.close();
				return;
			}
			first = frame;
		},
		error: onError
	});
	const demuxer = new Mp4Demuxer({ error: onError });
	try {
		await demuxer.loadBuffer(data);
		const config = demuxer.videoDecoderConfig;
		if (!config) err({ bytes: data.length });
		decoder.configure({
			codec: config.codec,
			description: config.description,
			codedWidth: config.codedWidth,
			codedHeight: config.codedHeight
		});
		for await (const chunk of demuxer) {
			if (chunk.chunkType !== "video" || !chunk.videoChunk) continue;
			decoder.decode(chunk.videoChunk);
			await decoder.flush();
			if (cause) throw cause;
			if (first) break;
		}
		if (!first) {
			if (cause) throw cause;
			err({ bytes: data.length });
		}
		const width = first.codedWidth;
		const height = first.codedHeight;
		const pixels = new Uint8Array(width * height * 4);
		await first.copyTo(pixels, { format: "RGBA" });
		return {
			jpeg: Transformer.fromRgbaPixels(pixels, width, height).jpegSync(),
			width,
			height
		};
	} finally {
		first?.close();
		decoder.close();
		demuxer.close();
	}
}
//#endregion
//#region src/message/core.ts
function encodeReference(reference) {
	return {
		referencedMessageId: LONG.fromString(reference.referencedMessageId),
		hint: reference.hint,
		...reference.rootMessageId ? { rootMessageId: LONG.fromString(reference.rootMessageId) } : {},
		...reference.rootMessageConvIndex ? { rootMessageConvIndex: LONG.fromString(reference.rootMessageConvIndex) } : {}
	};
}
/** cmd=100 /v1/message/send — 统一发送（文本/媒体/引用/编辑/盖楼全走 HTTP）。 */
async function send$1(ctx, options) {
	const clientMessageId = options.clientMessageId ?? randomUUID();
	const timestamp = Date.now();
	const result = parseSendResponse(await ctx.transport.sendCookieProto(100, options.inboxType ?? 0, "/v1/message/send", { sendMessage: {
		conversationId: options.conversationId,
		conversationType: options.conversationType ?? 1,
		conversationShortId: LONG.fromString(options.conversationShortId || "0"),
		content: normalizeDesktopTextMessageContent(options.content, options.messageType ?? 7),
		messageType: options.messageType ?? 7,
		clientMessageId,
		ext: {
			"s:mentioned_users": options.atAll ? "0" : "",
			"s:client_message_id": clientMessageId,
			"s:stime": `${timestamp}.${String(timestamp % 1e4).padStart(4, "0")}`
		},
		...options.reference ? { refMsgInfo: encodeReference(options.reference) } : {},
		...options.atAll ? { mentionedUsers: [LONG.fromString("0")] } : options.mentionedUsers?.length ? { mentionedUsers: options.mentionedUsers.map((uid) => LONG.fromString(uid)) } : {}
	} }, ctx.deviceId), clientMessageId);
	if (result.checkCode === 10502) ctx.log.info("消息已提交，审核中（10502），对方可能延迟可见");
	else if (result.statusCode !== 0) ctx.log.warn(`发送被拒: send={id:${options.conversationId} type:${options.conversationType ?? 1} short:${options.conversationShortId}} statusCode=${result.statusCode} check=${result.checkCode ?? "-"} detail=${result.statusMsg}`);
	return result;
}
/** body.sendMessageBody 解析：serverMessageId/status/checkCode/checkMessage */
function parseSendResponse(decoded, clientMessageId) {
	const statusCode = Number(decoded["statusCode"] ?? 0);
	const sendBody = decoded["body"]?.["sendMessage"];
	const rawCheckCode = Number(sendBody?.checkCode ?? 0);
	let checkCode = rawCheckCode > 0 ? rawCheckCode : void 0;
	let checkTips = "";
	if (sendBody?.checkMessage) try {
		const check = JSON.parse(sendBody.checkMessage);
		if (Number(check.status_code) > 0) checkCode = Number(check.status_code);
		checkTips = String(check.tips ?? "");
	} catch {}
	const sendStatus = Number(sendBody?.status ?? 0);
	const serverMessageId = sendBody?.serverMessageId != null ? String(sendBody.serverMessageId) : void 0;
	const envelopeMsg = String(decoded["errorDesc"] ?? "");
	if (!(statusCode === 0 && sendStatus === 0 && !!serverMessageId && serverMessageId !== "0")) return {
		statusCode: statusCode || sendStatus || -1,
		statusMsg: checkTips || envelopeMsg || "send rejected",
		clientMessageId,
		...checkCode !== void 0 ? { checkCode } : {}
	};
	return {
		statusCode: 0,
		statusMsg: envelopeMsg,
		serverMessageId,
		clientMessageId: sendBody?.clientMessageId ?? clientMessageId,
		...checkCode !== void 0 ? { checkCode } : {}
	};
}
//#endregion
//#region src/message/rich.ts
function buildImageContent(image) {
	return JSON.stringify({
		resource_url: {
			oid: image.oid,
			skey: image.skey,
			data_size: image.dataSize,
			md5: image.md5
		},
		cover_height: image.height,
		cover_width: image.width,
		check_pics: [],
		md5: image.md5,
		from_gallery: 1,
		aweType: image.format === "gif" ? 2703 : 2702
	});
}
/** 文件消息 content（messageType=6，aweType=15001，字段与官方接收样例同形） */
function buildFileContent(file) {
	return JSON.stringify({
		aweType: 15001,
		uri: file.uri,
		skey: file.skey,
		md5: file.md5,
		name: file.name,
		data_size: file.dataSize,
		format: file.name.includes(".") ? file.name.split(".").pop().toLowerCase() : "",
		createdAt: 0,
		is_card: false,
		msgHint: ""
	});
}
function buildVideoContent(video) {
	return JSON.stringify({
		video: {
			tkey: video.tkey,
			md5: video.md5,
			skey: video.skey
		},
		...video.poster ? { poster: {
			oid: video.poster.oid,
			md5: video.poster.md5,
			skey: video.poster.skey
		} } : {},
		...video.width !== void 0 ? { width: video.width } : {},
		...video.height !== void 0 ? { height: video.height } : {},
		check_pics: video.checkPics ?? []
	});
}
/** 作品分享卡片 content（messageType=8 / aweType=800，结构对齐 Android 分享帧），share_id 首段为自己的 uid */
function buildShareContent(item, senderUid) {
	const image = (uri) => ({
		data_size: 0,
		height: 720,
		uri,
		url_list: [uri],
		width: 540
	});
	return JSON.stringify({
		aweType: 800,
		awemeType: 0,
		content_name: item.authorName ?? "",
		content_title: item.title ?? item.itemId,
		...item.coverUrl ? {
			cover_height: 1440,
			cover_url: image(item.coverUrl),
			cover_width: 2560
		} : {},
		createdAt: 0,
		is_aigc: false,
		is_card: false,
		is_hot_spot_video: false,
		is_story: false,
		itemId: item.itemId,
		item_mask_status: 0,
		msgHint: "",
		need_skip_strange: 0,
		scene_type: 0,
		...item.secUid ? { secUID: item.secUid } : {},
		share_id: `${senderUid}_${Date.now()}_${item.itemId}`,
		share_with_timestamp: -1,
		uid: item.uid
	});
}
/** 用户名片卡片 content（messageType=25 / aweType=0，结构对齐 Android 名片帧）；uid 与 secUid 须真实，服务端可能据 uid 重建 */
function buildUserCardContent(item) {
	return JSON.stringify({
		...item.avatarUrl ? { avatar: {
			data_size: 0,
			height: 0,
			uri: item.avatarUrl,
			url_list: [item.avatarUrl],
			width: 0
		} } : {},
		aweType: 0,
		createdAt: 0,
		...item.coverItems?.length ? { cover_items: item.coverItems } : {},
		...item.coverUrls?.length ? { cover_url: item.coverUrls.map((url) => ({
			data_size: 0,
			height: 0,
			uri: "",
			url_list: [url],
			width: 0
		})) } : {},
		...item.desc ? { desc: item.desc } : {},
		...item.followerCount ? { follower_count: item.followerCount } : {},
		is_card: false,
		is_secret: false,
		msgHint: "",
		name: item.name ?? "",
		push_detail: item.name ?? "",
		...item.secUid ? { secUID: item.secUid } : {},
		source: "private_chat",
		uid: item.uid
	});
}
/** 构造互动卡 content（messageType=110）：description/push_detail 即展示文本，patch 原样回填，aweType 还原接收值 */
function buildCardContent(card, title) {
	return JSON.stringify({
		aweType: card.aweType || 110402,
		im_dynamic_patch: card.patch,
		description: title,
		push_detail: title
	});
}
/** 构造表情消息 content（messageType=5 / lite_emoji）：字段与官方发送样本逐一同形；url 必须传 im-resource 域直链，tos-cn 表态域会被服务端注入 s:visible 导致仅自身可见 */
function buildEmojiContent(url, displayName = "[表情]") {
	return JSON.stringify({
		display_name: displayName,
		height: 100,
		width: 100,
		image_id: 0,
		image_type: "png",
		package_id: 0,
		show_notice: false,
		resource_type: 4,
		emoji_from: "action_bar",
		emoji_source: "system_provided",
		emoji_type: "lite_emoji",
		sticker_type: 12,
		version: "2",
		updateConversationTime: true,
		url: {
			height: 100,
			data_size: 0,
			uri: url,
			url_list: [url],
			width: 100
		},
		createdAt: 0,
		is_card: false,
		msgHint: "",
		aweType: 507
	});
}
/** 构造位置消息 content（messageType=502 POI 定位）：字段与官方接收样例同形，封面用 cover_info.resource_url */
function buildLocationContent(location) {
	return JSON.stringify({
		aweType: 0,
		...location.awemePoiId ? { aweme_poi_id: location.awemePoiId } : {},
		cover_info: { resource_url: {
			data_size: 0,
			height: 0,
			uri: location.uri ?? "",
			url_list: location.urlList ?? [],
			width: 0
		} },
		createdAt: 0,
		is_card: false,
		latitude: location.latitude,
		longitude: location.longitude,
		msgHint: "",
		poi_address: location.address,
		...location.poiId ? { poi_id: location.poiId } : {},
		poi_name: location.name
	});
}
/** 构造群聊邀请卡 content（messageType=58 / aweme_invite_card）；from_uid 缺省以发送者身份填充，title/desc 参照官方文案 */
function buildGroupCardContent(card, senderUid) {
	const name = card.groupName;
	const inviter = card.fromNickname ?? card.fromUid ?? senderUid;
	return JSON.stringify({
		aweme_invite_card: {
			scene: 0,
			card_type: 1,
			...card.iconUrl ? { group_icon: { url_list: [card.iconUrl] } } : {},
			group_name: name,
			...card.memberCount !== void 0 ? { group_member_count: card.memberCount } : {},
			conversation_id: card.conversationId,
			conversation_short_id: card.conversationId,
			...card.ownerNickname ? { group_owner_nickname: card.ownerNickname } : {},
			from_uid: card.fromUid ?? senderUid,
			...card.fromSecUid ? { sec_from_uid: card.fromSecUid } : {},
			group_create_type: "0",
			need_cut_icon: 1,
			...card.ownerUid ? { group_owner_uid: card.ownerUid } : {},
			...card.ownerSecUid ? { sec_group_owner_uid: card.ownerSecUid } : {},
			source: 0,
			...card.ticket ? { ticket: card.ticket } : {}
		},
		title: `邀请你加入「${name}」`,
		desc: `${inviter} 邀请你加入「${name}」群聊，快来看下吧。`,
		type_desc: `${name}群聊`,
		push_detail: `邀请你加入${name}`
	});
}
//#endregion
//#region src/message/forward.ts
/** JSON 序列化：BigInt 输出为裸数字（uid/msg_id 等 19 位大整数超出 Number 精度，服务端按数字解析） */
function rawJson(value) {
	return JSON.stringify(value, (_, v) => typeof v === "bigint" ? `@@${v}@@` : v).replace(/"@@(-?\d+)@@"/g, "$1");
}
/** 合并转发 content：list_content 摘要 + msg_ids 引用，19 位 id 以裸数字写入；缺 msgId 的节点用伪 id 占位 */
function mergeContent(nodes, shortId, title) {
	const timestamp = Date.now();
	const ids = nodes.map((node, i) => node.msgId !== void 0 ? BigInt(node.msgId) : BigInt(timestamp) * 1000n + BigInt(i));
	return rawJson({
		list_content: nodes.map((node, i) => ({
			msgid: ids[i],
			nick_name: node.nickname,
			text: node.text
		})),
		msg_ids: nodes.map((node, i) => ({
			msg_id: ids[i],
			msg_type: node.msgType,
			awe_type: node.aweType,
			show_flag: true,
			uid: BigInt(node.uid),
			...node.secUid ? { sec_uid: node.secUid } : {},
			create_time: node.createTime ?? timestamp,
			ref_msg_invisible: 0
		})),
		new_mr_share_version: 2,
		origin_conv_id: BigInt(shortId),
		title: title ?? `${nodes[0]?.nickname ?? ""} 的聊天记录`,
		createdAt: 0,
		is_card: false,
		msgHint: "",
		aweType: 13600
	});
}
/**
* 合并转发（messageType=136）：list_content 为节点预览摘要，msg_ids 引用会话真实消息
* （msg_id 须为原消息 serverMessageId）。协议限制：新版 App 点开按 upload_key 从云端拉取
* 记录渲染，而云端注册接口 merge_msg_card/prepare 仅部署在 App 域（需 App 签名与登录态，
* web/桌面域 status 4），故 SDK 只能发摘要卡片，接收端点开无内容。
*/
async function sendMergeForward(ctx, options) {
	if (!options.nodes.length) return err({ nodes: options.nodes });
	const content = mergeContent(options.nodes, options.conversationShortId);
	return send$1(ctx, {
		...options,
		content,
		messageType: 136
	});
}
//#endregion
//#region src/message/emoji.ts
/**
* 官方小表情全量映射（214 项），即官方表情面板「小表情」分区数据源。
* 键值以文本形式收发（如消息里的 [微笑]），不做图片消息；tos-cn 域资源发 lite_emoji 会被服务端注入 s:visible 仅发送者可见
*/
async function getEmojiList(http) {
	return ((await http.json(`${site.web}${api.emojiList}`, { headers: { Referer: site.referer } })).data?.emoji_list ?? []).filter((e) => !e.hide && e.display_name).map((e) => ({
		id: (e.origin_uri ?? "").replace(/\.png$/, ""),
		name: e.display_name,
		uri: e.emoji_url?.uri ?? "",
		urls: e.emoji_url?.url_list ?? []
	}));
}
/** 小表情键值缓存：官方键值长期稳定，缓存只为省去每次发送都拉全量列表 */
let emojiCache;
/** 小表情 id（如 weixiao）→ 显示键值（[微笑]）；未收录返回 undefined。命中后按官方文本形态发送 */
async function emojiTextOf(http, id) {
	if (!emojiCache || Date.now() - emojiCache.at > time$1.emoji) {
		const map = new Map((await getEmojiList(http)).map((e) => [e.id, e.name]));
		emojiCache = {
			at: Date.now(),
			map
		};
	}
	return emojiCache.map.get(id);
}
/**
* 表情资源列表：/aweme/v1/web/im/resource/list/aggregation/，scenes 决定返回哪套贴纸。
* 对应官方面板「收藏」「GIF」分区（浏览器实测收藏资源域 im-emoticon、s=im_123；GIF 为 s=im_124）。
* 仅浏览器环境可用：无 a_bogus 签名时服务端返回文本 blocked（非 JSON），SDK 环境优先用 emojiTrending
*/
async function stickerList(http, options = {}) {
	const scenes = options.scenes ?? "CUSTOM_STICKER_PAGE";
	const params = new URLSearchParams({
		device_platform: "webapp",
		aid: "1128",
		app_id: "1128",
		channel: "channel_pc_web",
		scenes,
		source: scenes,
		custom_cursor: String(options.cursor ?? 0),
		custom_limit: String(options.limit ?? 50)
	});
	const res = await http.json(`${site.web}${api.resourceList}?${params}`, { headers: { Referer: site.web } });
	if (Number(res.data.status_code ?? 0) !== 0) return err(res.data);
	const bean = Object.values(res.data).find(isPageBean);
	if (!bean || !bean.resources) return {
		list: [],
		total: 0,
		cursor: 0,
		done: true
	};
	const stickers = [];
	for (const r of bean.resources) {
		const rec = r;
		if (Array.isArray(rec["stickers"])) stickers.push(...rec["stickers"]);
	}
	return {
		list: stickers.map(stickerOf),
		total: Number(bean.total_counts ?? 0),
		cursor: Number(bean.next_cursor ?? 0),
		done: bean.is_completed === true
	};
}
/** 收藏/取消收藏表情：/aweme/v1/web/im/resource/sticker/collect/，参数全部走 query，body 为固定 {} */
async function stickerCollect(http, ids, options = {}) {
	const params = new URLSearchParams({
		action: options.remove ? "1" : "0",
		sticker_ids: `[${ids.join(",")}]`,
		sticker_uri: options.uri ?? "",
		sticker_url: options.url ?? "",
		resource_id: "0",
		sticker_type: "0"
	});
	const res = await http.json(`${site.web}${api.stickerCollect}?${params}`, {
		method: "POST",
		headers: {
			Referer: site.web,
			"Content-Type": "application/json"
		},
		body: "{}"
	});
	if (Number(res.data.status_code ?? 0) !== 0) return err(res.data);
	return { ids: (res.data.success_items ?? []).map((s) => s.id_str ?? String(s.id ?? "")) };
}
/**
* emoticon/trending:热门表情分页（cursor+count 翻页，groupId 固定 1）。
* 对应官方面板「贴纸」分区（官方互动贴纸，im-resource 域 s=im_111/im_2），是 lite_emoji 表情消息的推荐数据源
*/
async function emojiTrending(http, options = {}) {
	const params = new URLSearchParams({
		cursor: String(options.cursor ?? 0),
		count: String(options.count ?? 50),
		groupId: "1"
	});
	const data = (await http.json(`${site.web}${api.trending}?${params}`, { headers: { Referer: site.web } })).data?.emoticon_data;
	return {
		list: (data?.stickers ?? []).map((raw) => stickerOf(raw)),
		total: 0,
		cursor: Number(data?.next_cursor ?? 0),
		done: data?.has_more !== true
	};
}
/** trending 短缓存：签名链接有效期极长（至 2027），缓存只为省去每次发表情都拉列表 */
let trendingCache;
/**
* 表情消息 URL 归一化：完整 URL 原样返回；否则视为 im-resource 资源 id，
* 经 trending 匹配出带签名的 CDN 直链（签名时效长，缓存放大到 5 分钟）；列表未收录时退回无签名直链
*/
async function stickerUrlOf(http, emoji) {
	if (/^https?:\/\//.test(emoji)) return emoji;
	if (!trendingCache || Date.now() - trendingCache.at > time$1.trending) {
		const page = await emojiTrending(http);
		trendingCache = {
			at: Date.now(),
			page
		};
	}
	for (const s of trendingCache.page.list) {
		const img = s.static ?? s.animate;
		if (!img) continue;
		if (img.uri.includes(emoji) || img.urls.some((u) => u.includes(emoji))) return img.urls[0] ?? img.uri;
	}
	return `${site.cdn}${emoji}`;
}
/** strategy/config:app 能力开关（决策树 + 动效资源包配置） */
async function strategyConfig(http, scenes = ["interactive_resources"]) {
	const params = new URLSearchParams({
		app_id: "1128",
		scenes: JSON.stringify(scenes)
	});
	const res = await http.json(`${site.web}${api.strategy}?${params}`, { headers: { Referer: site.web } });
	return {
		...res.data?.decision_trees ? { decisionTrees: res.data.decision_trees } : {},
		...res.data?.interactive_resource_config ? { interactiveResourceConfig: res.data.interactive_resource_config } : {}
	};
}
/**
* privacy/batch_build_image:把图源 uri 渲染为打码图(分享卡片脱敏头像/昵称场景),
* desktop 指纹批 + JSON body,HAR 实证返回 pack_results[0].UrlList 直链列表
*/
async function privacyImage(http, uri, options = {}) {
	const params = fingerprintParams(http.deviceId, http.guid);
	const body = JSON.stringify({ convert_params: [{
		uri,
		format: options.format ?? "tplv-x-get:large.image",
		tpl: options.tpl ?? "%s://%v/%v~%v"
	}] });
	const res = await http.json(`${site.web}${api.privacy}?${params}`, {
		method: "POST",
		headers: {
			Referer: site.web,
			"Content-Type": "application/json"
		},
		body
	});
	const list = res.data?.data?.pack_results?.[0]?.UrlList;
	if (!list) return err(res.data);
	return list.filter((u) => typeof u === "string");
}
function isPageBean(v) {
	return !!v && typeof v === "object" && Array.isArray(v.resources);
}
function stickerOf(raw) {
	return {
		id: typeof raw["id_str"] === "string" ? raw["id_str"] : String(raw["id"] ?? ""),
		type: Number(raw["sticker_type"] ?? 0),
		...typeof raw["display_name"] === "string" && raw["display_name"] ? { name: raw["display_name"] } : {},
		...typeof raw["hash"] === "string" ? { hash: raw["hash"] } : {},
		...typeof raw["sticker_info_source"] === "string" ? { source: raw["sticker_info_source"] } : {},
		...isImage(raw["static_url"]) ? { static: imageOf(raw["static_url"]) } : {},
		...isImage(raw["animate_url"]) ? { animate: imageOf(raw["animate_url"]) } : {}
	};
}
function isImage(v) {
	return !!v && typeof v === "object" && Array.isArray(v.url_list);
}
function imageOf(v) {
	return {
		width: Number(v.width ?? 0),
		height: Number(v.height ?? 0),
		uri: String(v.uri ?? ""),
		urls: v.url_list?.filter((u) => typeof u === "string") ?? []
	};
}
//#endregion
//#region src/message/payload.ts
const onText = (ctx, address, body, extra) => {
	const item = body;
	if (item.atAll) return send$1(ctx, {
		...address,
		content: buildAtAllTextContent(item.text),
		messageType: 7,
		atAll: true,
		...extra
	});
	const { content, mentions } = textWithAts(item.text, item.ats, address.conversationId);
	return send$1(ctx, {
		...address,
		content,
		messageType: 7,
		...mentions.length ? { mentionedUsers: [...new Set(mentions.map((m) => m.uid))] } : {},
		...extra
	});
};
const onImage = (ctx, address, body, extra) => {
	const item = body;
	if (isInput(item.image)) return err({ image: item.image });
	return sendImage(ctx, {
		...address,
		image: item.image,
		...extra
	});
};
const onVideo = (ctx, address, body, extra) => {
	const video = body.video;
	if ("source" in video) return err({ video });
	if (!("asset" in video)) return sendVideo(ctx, {
		...address,
		video,
		...extra
	});
	const { asset, poster, width, height } = video;
	return sendVideo(ctx, {
		...address,
		video: {
			tkey: asset.tkey,
			skey: asset.skey,
			md5: asset.md5,
			...poster ? { poster } : {},
			...width !== void 0 ? { width } : {},
			...height !== void 0 ? { height } : {}
		},
		...extra
	});
};
const onFile = (ctx, address, body, extra) => {
	const file = body.file;
	if ("source" in file) return err({ file });
	return sendFile(ctx, {
		...address,
		file: "asset" in file ? file.asset : file,
		...extra
	});
};
const onShare = (ctx, address, body, extra) => sendShare(ctx, {
	...address,
	item: body.share,
	...extra
});
const onUserCard = (ctx, address, body, extra) => sendUserCard(ctx, {
	...address,
	user: body.user,
	...extra
});
const onForward = (ctx, address, body, extra) => sendMergeForward(ctx, {
	...address,
	nodes: body.nodes,
	selfUid: ctx.userId,
	...extra
});
const onEmoji = async (ctx, address, body, extra) => {
	const item = body;
	const text = await emojiTextOf(ctx.http, item.emoji);
	if (text) return send$1(ctx, {
		...address,
		content: text,
		messageType: 7,
		...extra
	});
	return send$1(ctx, {
		...address,
		content: buildEmojiContent(await stickerUrlOf(ctx.http, item.emoji), item.text),
		messageType: 5,
		...extra
	});
};
const onCard = (ctx, address, body, extra) => {
	const item = body;
	return send$1(ctx, {
		...address,
		content: buildCardContent(item.card, item.text ?? item.card.title ?? ""),
		messageType: 110,
		...extra
	});
};
const onLocation = (ctx, address, body, extra) => send$1(ctx, {
	...address,
	content: buildLocationContent(body.location),
	messageType: 502,
	...extra
});
const onGroupCard = (ctx, address, body, extra) => {
	const item = body;
	return send$1(ctx, {
		...address,
		content: buildGroupCardContent(item.groupCard, ctx.userId),
		messageType: 58,
		...extra
	});
};
/** 消息类型 → 发送策略：text/媒体/卡片/转发各一条消息，新增类型只注册不分支 */
const handlers = /* @__PURE__ */ new Map([
	["text", onText],
	["image", onImage],
	["video", onVideo],
	["file", onFile],
	["share", onShare],
	["userCard", onUserCard],
	["forward", onForward],
	["emoji", onEmoji],
	["card", onCard],
	["location", onLocation],
	["groupCard", onGroupCard]
]);
/**
* 统一发送：type 判别各成一条消息（text 合 messageType=7、image 27 / video 30 / file 6 /
* share 8 / user 25 / forward 136）；媒体字段须为已上传资产，输入源先经 bot.msg.send 自动上传。
*/
async function sendBody(ctx, address, body, opts) {
	const handler = handlers.get(body.type);
	if (!handler) {
		ctx.log.warn(`不支持发送的消息类型 ${body.type}，已跳过`);
		return err({ type: body.type });
	}
	return handler(ctx, address, body, {
		clientMessageId: opts?.clientMessageId,
		reference: opts?.reference
	});
}
/** 发送图片（gif → aweType 2703，其余 2702；messageType=27） */
async function sendImage(ctx, options) {
	return send$1(ctx, {
		...options,
		content: buildImageContent(options.image),
		messageType: 27
	});
}
/** 发送视频（messageType=30，content 无 aweType） */
async function sendVideo(ctx, options) {
	return send$1(ctx, {
		...options,
		content: buildVideoContent(options.video),
		messageType: 30
	});
}
/** 发送文件（messageType=6、aweType=15001；9 会被客户端判「请升级最新版」，6 可发出但部分客户端渲染异常） */
async function sendFile(ctx, options) {
	return send$1(ctx, {
		...options,
		content: buildFileContent(options.file),
		messageType: 6
	});
}
/** 发送作品分享卡片（messageType=8 / aweType=800） */
async function sendShare(ctx, options) {
	return send$1(ctx, {
		...options,
		content: buildShareContent(options.item, ctx.userId),
		messageType: 8
	});
}
/** 发送用户名片卡片（messageType=25 / aweType=0） */
async function sendUserCard(ctx, options) {
	return send$1(ctx, {
		...options,
		content: buildUserCardContent(options.user),
		messageType: 25
	});
}
//#endregion
//#region src/message/send.ts
/**
* 上报输入状态（让对方显示「正在输入…」）。
* 走 Android Frontier WS cmd=411（接收侧是 WS 504 推送）。
* 无确认回执（fire-and-forget），返回 true 仅表示帧已发出。
*/
async function sendTyping(ctx, address, typing) {
	return sendCmd411({
		userId: ctx.userId,
		cookies: ctx.cookies,
		conversationId: address.conversationId,
		conversationShortId: address.conversationShortId || "0",
		conversationType: address.conversationType ?? 1,
		typing
	});
}
/**
* 发起语音通话——未支持。
* 实测证伪（保留签名便于收敛）：cmd2011/2012 走 Android WS 服务端仅回框架 ACK 无业务响应；
* imapi3 HTTP 通道路由表（StatusCodeRouteNotFound 全量列举）无任何 voip/voice 命令；
* 官方桌面端 VOIP 走独立未公开端点（需 App 专属签名）。不再发起任何网络请求。
*/
async function startVoiceCall(ctx, address, calleeUid) {
	ctx.log.warn(`语音通话未支持: 被叫=${calleeUid} 会话=${address.conversationShortId || "-"}`);
	return {
		statusCode: -1,
		checkMessage: "服务端无 VOIP 通道"
	};
}
//#endregion
//#region src/message/action.ts
/** cmd=705, /v1/message/set_property — 消息表情回应（operation 0=添加 1=移除） */
async function modifyReaction(ctx, options) {
	const decoded = await ctx.transport.sendCookieProto(705, options.inboxType ?? 0, "/v1/message/set_property", { modifyMessageProperty: {
		propertyList: [{
			conversationId: options.conversationId,
			conversationType: options.conversationType ?? 1,
			conversationShortId: LONG.fromString(options.conversationShortId || "0"),
			serverMessageId: LONG.fromString(options.serverMessageId),
			clientMessageId: "",
			modifyPropertyContent: [{
				operation: options.enabled ? 0 : 1,
				key: `se:${options.emoji}`,
				value: "",
				idempotentId: options.operatorUid
			}]
		}],
		ticket: ""
	} }, ctx.deviceId);
	const envelopeStatus = Number(decoded["statusCode"] ?? 0);
	return {
		statusCode: envelopeStatus === 1 ? 0 : envelopeStatus,
		statusMsg: String(decoded["errorDesc"] ?? "")
	};
}
/** 会话标记已读：cmd=2002 mark_conversation_read（对齐 native rawMarkConversationRead，body oneof tag 604） */
async function markConversationRead(ctx, options) {
	const send = async (endpoint) => ctx.transport.sendCookieProto(2002, options.inboxType ?? 1, endpoint, { markConversationRead: {
		conversationId: options.conversationId,
		conversationShortId: LONG.fromString(options.conversationShortId || "0"),
		conversationType: options.conversationType ?? 1,
		readMessageIndex: LONG.fromString(options.readMessageIndex ?? "0"),
		readMessageIndexV2: LONG.fromString(options.readMessageIndexV2 ?? "0"),
		convUnreadCount: LONG.fromString("0"),
		totalUnreadCount: LONG.fromString("0"),
		readBadgeCount: 0,
		serverMessageId: LONG.fromString(options.serverMessageId ?? "0"),
		ticket: ""
	} }, ctx.deviceId);
	let decoded = await send("/v1/conversation/mark_read");
	if (Number(decoded["statusCode"] ?? 0) !== 0 && Number(decoded["statusCode"] ?? 0) !== 1) decoded = await send("/v3/conversation/mark_read");
	const envelopeStatus = Number(decoded["statusCode"] ?? 0);
	return {
		statusCode: envelopeStatus === 1 ? 0 : envelopeStatus,
		statusMsg: String(decoded["errorDesc"] ?? "")
	};
}
/** cmd=702, /v1/message/recall — 撤回已投递消息 */
async function recall(ctx, options) {
	const decoded = await ctx.transport.sendCookieProto(702, options.inboxType ?? 0, "/v1/message/recall", { recallMessage: {
		conversationId: options.conversationId,
		conversationShortId: LONG.fromString(options.conversationShortId || "0"),
		conversationType: options.conversationType ?? 1,
		serverMessageId: LONG.fromString(options.serverMessageId)
	} }, ctx.deviceId);
	const envelopeStatus = Number(decoded["statusCode"] ?? 0);
	const actionStatus = (decoded["body"]?.["recallMessage"])?.status ?? 0;
	return {
		statusCode: envelopeStatus || actionStatus,
		statusMsg: String(decoded["errorDesc"] ?? ""),
		recalled: envelopeStatus === 0 && actionStatus === 0
	};
}
//#endregion
//#region src/bot/msg.ts
var Msg = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 统一发送：type 判别一条消息；媒体输入源自动上传，收侧消息对象可直接回传当引用 */
	async send(chatId, body, opts) {
		const reference = opts?.reply ? referenceOf(opts.reply) : opts?.reference;
		return sendBody(this.bot.ctx().send, toAddress(chatId), await this.prepare(body), {
			...opts?.clientMessageId ? { clientMessageId: opts.clientMessageId } : {},
			...reference ? { reference } : {}
		});
	}
	/** 编辑不支持：HTTP 复用原 cmid 会被服务端幂等去重，官方编辑走 App 专属通道 */
	async edit(chatId, clientMessageId, body) {
		return sendBody(this.bot.ctx().send, toAddress(chatId), await this.prepare(body), { clientMessageId });
	}
	/** 媒体输入源归一化：简写源先上传为资产，预上传 asset 原样透传 */
	async prepare(body) {
		const uploader = this.bot.ctx().uploader;
		if (body.type === "text" && body.ats?.some((at) => !at.nickname)) {
			const ats = await Promise.all(body.ats.map(async (at) => ({
				...at,
				nickname: at.nickname ?? await this.bot.nickOf(at.uid)
			})));
			return {
				...body,
				ats
			};
		}
		if (body.type === "image") {
			if (!isInput(body.image)) return body;
			return {
				...body,
				image: await uploader.uploadImage(await resolveMedia(body.image))
			};
		}
		if (body.type === "video") {
			const video = body.video;
			if (!("source" in video)) return body;
			const bytes = await resolveMedia(video.source);
			const dims = await probeVideo(bytes);
			let width = video.width ?? dims.width;
			let height = video.height ?? dims.height;
			let poster = video.poster;
			if (poster !== void 0) poster = isInput(poster) ? await uploader.uploadImage(await resolveMedia(poster)) : poster;
			else {
				const shot = await extractVideoPoster(bytes);
				poster = await uploader.uploadImage(shot.jpeg);
				width ||= shot.width;
				height ||= shot.height;
			}
			return {
				...body,
				video: {
					asset: await uploader.uploadVideo(bytes),
					poster,
					width: width > 0 ? width : void 0,
					height: height > 0 ? height : void 0
				}
			};
		}
		if (body.type === "file") {
			const file = body.file;
			if (!("source" in file)) return body;
			return {
				...body,
				file: { asset: await uploader.uploadFile(await resolveMedia(file.source), file.name ?? fileNameOf(file.source)) }
			};
		}
		return body;
	}
	/** 上报输入状态（true 正在输入 / false 停止） */
	sendTyping(chatId, typing) {
		return sendTyping(this.bot.ctx().send, toAddress(chatId), typing);
	}
	/** 发起语音通话（服务端无 VOIP 通道，返回 statusCode=-1） */
	call(chatId, calleeUid) {
		return startVoiceCall(this.bot.ctx().send, toAddress(chatId), calleeUid);
	}
	/** 引用回复：任意消息类型均可引，body 可为文本或任意消息体；文本为空不发送 */
	async reply(chatId, msg, body, opts) {
		const content = typeof body === "string" ? {
			type: "text",
			text: body,
			...opts?.atAll ? { atAll: true } : {},
			...opts?.ats?.length ? { ats: opts.ats } : {}
		} : body;
		if (content.type === "text" && !content.text.trim()) return err({ text: content.text });
		return this.send(chatId, content, { reply: msg });
	}
	recall(chatId, serverMessageId) {
		const item = {
			...toAddress(chatId),
			serverMessageId
		};
		return recall(this.bot.ctx().inbox, item);
	}
	/** 表情回应：emoji 传抖音键值（如 '[爱心]'）或小表情 id（如 weixiao），isSet false 取消 */
	async react(chatId, serverMessageId, emoji, isSet = true) {
		const skey = await emojiTextOf(this.bot.ctx().http, emoji) ?? emoji;
		return modifyReaction(this.bot.ctx().inbox, {
			...toAddress(chatId),
			serverMessageId,
			emoji: skey,
			operatorUid: this.bot.id,
			enabled: isSet
		});
	}
	/** 标记已读；msg 缺省读到底 */
	read(chatId, msg) {
		const item = {
			...toAddress(chatId),
			readMessageIndex: msg?.createTime,
			readMessageIndexV2: msg?.indexInConversationV2,
			serverMessageId: msg?.serverMessageId
		};
		return markConversationRead(this.bot.ctx().inbox, item);
	}
};
//#endregion
//#region src/media/peer.ts
/** vc-gate-edge get_peer:按文件信息调度 CDN 传输节点（Result 字段映射为 camelCase） */
async function getPeer(http, req) {
	const res = await http.json(site.peer, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			app_id: req.appId ?? ver.webAid,
			sid: req.sid ?? 5,
			task_type: req.taskType ?? 1,
			file_info: req.fileInfo
		})
	});
	const result = res.data?.Result;
	if (!result) err(res.data);
	return {
		status: result.status ?? -1,
		fid: result.fid ?? "",
		traceId: result.trace_id ?? "",
		reqId: result.req_id ?? "",
		token: result.token ?? "",
		nodes: result.nodes ?? [],
		...result.multi_nodes != null ? { multiNodes: result.multi_nodes } : {},
		indexNum: result.index_num ?? 0,
		countryCode: result.country_code ?? 0,
		ispCode: result.isp_code ?? 0
	};
}
//#endregion
//#region src/bot/media.ts
var Media$1 = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 图片上传：url/路径/base64/字节均可 */
	async image(input) {
		return this.bot.ctx().uploader.uploadImage(await resolveMedia(input));
	}
	/** 视频上传：url/路径/base64/字节均可 */
	async video(input) {
		return this.bot.ctx().uploader.uploadVideo(await resolveMedia(input));
	}
	/** 文件上传：名字缺省从来源推断 */
	async file(input, name) {
		return this.bot.ctx().uploader.uploadFile(await resolveMedia(input), name ?? fileNameOf(input));
	}
	/** 用消息视频的 tkey 换加密 CDN 播放地址（CENC 流，需解密后才能播放） */
	videoUrl(tkey) {
		return getVideoUrl(this.bot.ctx().http, tkey);
	}
	/** 按 awemeId 批量拉作品详情（视频/图文） */
	awemeDetail(awemeIds, options) {
		return awemeDetail(this.bot.ctx().http, awemeIds, options);
	}
	/** CDN 传输节点调度（按文件信息选可用节点） */
	getPeer(req) {
		return getPeer(this.bot.ctx().http, req);
	}
	/** 官方表情资源全量映射（id/键值/CDN 直链） */
	emojiList() {
		return getEmojiList(this.bot.ctx().http);
	}
};
//#endregion
//#region src/bot/frd.ts
var Frd = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 分页参数：cursor 起始游标，count 单页条数；缺省自动翻页拉全量 */
	async list(options = {}) {
		const list = await getFriendList(this.bot.ctx().inbox, options);
		this.bot.rememberNicks(list);
		return list.map((f) => ({
			chatId: chatIdOf({
				...f,
				conversationType: 1
			}),
			...f
		}));
	}
	async requests(status) {
		const list = await getFriendRequests(this.bot.ctx().inbox, status ? { status } : {});
		this.bot.rememberNicks(list.map((r) => ({
			uid: r.applicantUid,
			nickname: r.nickname
		})));
		return list;
	}
	approve(uid) {
		return reviewFriendRequest(this.bot.ctx().inbox, uid, 2);
	}
	reject(uid) {
		return reviewFriendRequest(this.bot.ctx().inbox, uid, 3);
	}
};
//#endregion
//#region src/chat/list.ts
/**
* cmd=2006 会话列表：响应不回传翻页游标，服务端按请求 cursor 做 offset 式推进，
* 不足一页即到底；忽略 cursor 时会恒回同一批，因此按 shortId 去重。
*/
async function collect(ctx, options, native) {
	const all = [];
	const seen = /* @__PURE__ */ new Set();
	let cursor = options.cursor ?? 0;
	for (;;) {
		const limit = options.count ?? 20;
		const request = { conversationList: {
			listType: 1,
			cursor,
			sortType: 2,
			limit
		} };
		const decoded = native ? await ctx.transport.sendNativeProto(2006, 0, "/v1/conversation/list", request, ctx.deviceId) : await ctx.transport.sendCookieProto(2006, 0, "/v1/conversation/list", request, ctx.deviceId);
		if (Number(decoded["statusCode"] ?? 0) !== 0) return err(decoded);
		const conversations = (decoded["body"]?.["conversationList"])?.conversations ?? [];
		const fresh = conversations.filter((conversation) => {
			const id = String(conversation["conversationShortId"] ?? "");
			if (!id || seen.has(id)) return false;
			seen.add(id);
			return true;
		});
		all.push(...fresh.map(mapProtoConversationListItem));
		if (conversations.length < limit || fresh.length === 0) break;
		cursor += conversations.length;
	}
	return all;
}
/** Desktop Cookie 通道会话列表 */
function listConversations(ctx, options = {}) {
	return collect(ctx, options, false);
}
/** 旧 Cookie 通道群列表（备用；群列表主用 listNativeGroups） */
async function listConversationsByCookie(ctx, options = {}) {
	return (await listConversations(ctx, options)).filter((conversation) => conversation.isGroup);
}
/** 群列表：原生通道 imapi.douyin.com（对齐官方 PC 群列表） */
async function listNativeGroups(ctx, options = {}) {
	return (await collect(ctx, options, true)).filter((conversation) => conversation.isGroup);
}
/** 群列表：原生通道全量群会话 */
function getGroupList(ctx, options = {}) {
	return listNativeGroups(ctx, options);
}
//#endregion
//#region src/chat/request.ts
/** 入群申请行映射；缺关键字段的行直接丢弃 */
function requestOf(value) {
	if (!value) return void 0;
	const requestId = String(value["applyId"] ?? "");
	const applicantUid = String(value["userId"] ?? "");
	const groupShortId = String(value["convShortId"] ?? "");
	if (!requestId || !applicantUid || !groupShortId) return void 0;
	const applicantSecUid = String(value["secUid"] ?? "");
	const reason = String(value["applyReason"] ?? "");
	const inviterUid = String(value["inviteUserId"] ?? "");
	const inviterSecUid = String(value["secInviteUid"] ?? "");
	const createdAt = String(value["createTime"] ?? "");
	const modifiedAt = String(value["modifyTime"] ?? "");
	const moderatorUid = String(value["modifyUser"] ?? "");
	const ext = value["ext"];
	return {
		requestId,
		applicantUid,
		groupShortId,
		conversationType: Number(value["conversationType"] ?? 2),
		status: Number(value["applyStatus"] ?? 1),
		...applicantSecUid ? { applicantSecUid } : {},
		...reason ? { reason } : {},
		...inviterUid && inviterUid !== "0" ? { inviterUid } : {},
		...inviterSecUid ? { inviterSecUid } : {},
		...createdAt && createdAt !== "0" ? { createdAt } : {},
		...modifiedAt && modifiedAt !== "0" ? { modifiedAt } : {},
		...moderatorUid && moderatorUid !== "0" ? { moderatorUid } : {},
		...ext && typeof ext === "object" ? { ext } : {}
	};
}
/** cmd=2027 入群申请列表 */
async function getGroupJoinRequests(ctx, options = {}) {
	const requests = [];
	let cursor = "0";
	for (;;) {
		const decoded = await ctx.transport.sendCookieProto(2027, 1, "/v1/conversation/get_audit_list", { getConversationAuditList: {
			cursor: LONG.fromString(cursor),
			limit: 100
		} }, ctx.deviceId);
		if (actionResponse(decoded).statusCode !== 0) return err(decoded);
		const body = decoded["body"]?.["getConversationAuditList"];
		for (const raw of body?.applyInfoList ?? []) {
			const request = requestOf(raw);
			if (request && (!options.conversationShortId || request.groupShortId === options.conversationShortId)) requests.push(request);
		}
		if (!body?.hasMore) return requests;
		const next = String(body.nextCursor ?? "");
		if (!next) return requests;
		cursor = next;
	}
}
/** cmd=2025 审批入群申请 */
async function reviewGroupJoinRequest(ctx, requestId, status) {
	const decoded = await ctx.transport.sendCookieProto(2025, 1, "/v1/conversation/ack_apply", { ackConversationApply: {
		applyId: LONG.fromString(requestId),
		applyStatus: status,
		bizExt: {}
	} }, ctx.deviceId);
	const result = actionResponse(decoded, "ackConversationApply");
	const body = decoded["body"]?.["ackConversationApply"];
	const request = requestOf(body?.applyInfo);
	return {
		...result,
		...request ? { request } : {}
	};
}
//#endregion
//#region src/chat/share.ts
function str$1(source, key) {
	return typeof source?.[key] === "string" ? String(source[key]) : "";
}
/** 解析邀请链接的 secret 与 group_id；纯 secret 直接使用 */
function parseShare(input) {
	const raw = input.share.trim();
	let secret = raw;
	let groupId = input.conversationId ?? "";
	if (/^https?:\/\//.test(raw)) {
		const params = new URL(raw).searchParams;
		secret = params.get("secret") ?? params.get("group_token") ?? secret;
		groupId = input.conversationId ?? params.get("group_id") ?? params.get("conversation_id") ?? "";
	}
	if (!secret || !groupId) return err({
		secret,
		groupId
	});
	return {
		secret,
		groupId
	};
}
/**
* 用群邀请 secret 换群邀请凭证：/aweme/v1/web/im_group_api/share/verification/。
* 实证该接口回读群资料，且返回的 ticket 即传入的 secret（同值 AAED 串），
* 与 610 会话详情下发的 ticket 是两条不同的串
*/
async function verifyShare(http, input) {
	const { secret, groupId } = parseShare(input);
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	const body = new URLSearchParams({
		ext: JSON.stringify({
			group_reserve_v2_ab: "2",
			join_source: "5"
		}),
		group_id: groupId,
		invite_card_scene: String(input.scene ?? 0),
		secret,
		secret_type: "4"
	}).toString();
	const res = await http.request(`${site.im}${api.shareVerify}?${params}`, {
		method: "POST",
		body,
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Referer: `${site.im}/chat`
		}
	});
	if (!res.ok) return err(res.data);
	const raw = JSON.parse(res.data.replace(/"(\w+)"\s*:\s*(\d{16,})/g, "\"$1\":\"$2\""));
	const detail = raw.data;
	if (!detail || str$1(detail, "ticket") === "") return err(raw);
	const owner = detail["group_owner_info"];
	return {
		ticket: str$1(detail, "ticket"),
		conversationId: str$1(detail, "conversation_id") || groupId,
		conversationShortId: str$1(detail, "conversation_short_id"),
		name: str$1(detail, "group_name"),
		desc: str$1(detail, "group_desc"),
		...str$1(detail, "group_avatar") ? { avatar: str$1(detail, "group_avatar") } : {},
		memberCount: Number(detail["group_member_count"] ?? 0),
		...str$1(owner, "owner_id") ? { ownerUid: str$1(owner, "owner_id") } : {},
		...str$1(owner, "sec_owner_id") ? { ownerSecUid: str$1(owner, "sec_owner_id") } : {},
		...str$1(owner, "owner_name") ? { ownerNickname: str$1(owner, "owner_name") } : {},
		...str$1(detail, "inviter_id") ? { inviterUid: str$1(detail, "inviter_id") } : {},
		...str$1(detail, "inviter_sec_uid") ? { inviterSecUid: str$1(detail, "inviter_sec_uid") } : {},
		...str$1(detail, "group_audit_question") ? { auditQuestion: str$1(detail, "group_audit_question") } : {}
	};
}
//#endregion
//#region src/bot/grp.ts
var Grp = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 分页参数：cursor 起始游标，count 单页条数；缺省自动翻页拉全量 */
	async list(options = {}) {
		return (await getGroupList(this.bot.ctx().inbox, options)).map((g) => ({
			chatId: chatIdOf(g),
			...g
		}));
	}
	async members(chatId) {
		const list = await getGroupMembers(this.bot.ctx().inbox, toAddress(chatId));
		this.bot.rememberNicks(list);
		return list;
	}
	/** 群入群申请；省略 chatId 查全部群 */
	async requests(chatId) {
		const shortId = chatId ? toAddress(chatId).conversationShortId : void 0;
		const list = await getGroupJoinRequests(this.bot.ctx().inbox, shortId ? { conversationShortId: shortId } : {});
		this.bot.rememberNicks(list.map((r) => ({
			uid: r.applicantUid,
			nickname: r.applicantNickname
		})));
		return list;
	}
	approve(requestId) {
		return reviewGroupJoinRequest(this.bot.ctx().inbox, requestId, 2);
	}
	reject(requestId) {
		return reviewGroupJoinRequest(this.bot.ctx().inbox, requestId, 3);
	}
	rename(chatId, name) {
		return setGroupName(this.bot.ctx().inbox, toAddress(chatId), name);
	}
	/** 拉人入群（cmd=650，成功/失败名单在返回里回读） */
	addMembers(chatId, uids) {
		return addGroupMembers(this.bot.ctx().inbox, toAddress(chatId), uids);
	}
	/** 移出群成员（cmd=651） */
	removeMembers(chatId, uids) {
		return removeGroupMembers(this.bot.ctx().inbox, toAddress(chatId), uids);
	}
	/** 退出群聊（cmd=652，响应为空 body） */
	leave(chatId) {
		return leaveGroup(this.bot.ctx().inbox, toAddress(chatId));
	}
	/** 创建群聊（cmd=609），返回会话（含 chatId） */
	async create(options) {
		const result = await createGroup(this.bot.ctx().inbox, options);
		return result.group ? {
			...result,
			chatId: chatIdOf(result.group)
		} : result;
	}
	/** 群分享校验：用邀请链接换群邀请凭证（ticket 可直接填入 groupCard.ticket 发卡） */
	verifyShare(input) {
		return verifyShare(this.bot.ctx().http, input);
	}
};
//#endregion
//#region src/chat/history.ts
/** cmd=301 会话历史消息 */
async function getChatHistory(ctx, options) {
	const decoded = await ctx.transport.sendCookieProto(301, 1, "/v1/message/get_by_conversation", { conversationMessages: {
		conversationId: options.conversationId,
		conversationType: options.conversationType,
		conversationShortId: LONG.fromString(options.conversationShortId),
		direction: 1,
		anchorIndex: options.cursor ?? 0,
		limit: options.count ?? 20
	} }, ctx.deviceId);
	if (Number(decoded["statusCode"] ?? 0) !== 0) return err(decoded);
	return ((decoded["body"]?.["conversationMessages"])?.messages ?? []).map((row) => mapProtoMessage(row));
}
//#endregion
//#region src/chat/info.ts
/** cmd=610 按 id 批量查会话详情（ticket/未读/成员），映射对齐列表会话 */
async function getInfoList(ctx, items) {
	if (items.length === 0) return [];
	return ((await ctx.transport.sendCookieProto(610, items[0]?.inboxType ?? 0, "/v2/conversation/get_info_list", { getConversationInfoListV2: { conversationInfoList: items.map((item) => ({
		conversationId: item.conversationId,
		conversationShortId: LONG.fromString(item.conversationShortId || "0"),
		conversationType: item.conversationType
	})) } }, ctx.deviceId))["body"]?.getConversationInfoListV2?.conversationInfoList ?? []).map(mapProtoConversationListItem);
}
//#endregion
//#region src/inbox/cursor.ts
/** cmd=2000 get_read_index:按会话查各成员已读游标 */
async function getReadIndex(ctx, item) {
	return ((await ctx.transport.sendCookieProto(2e3, item.inboxType ?? 0, "/v3/conversation/get_read_index", { getReadIndex: {
		conversationShortId: LONG.fromString(item.conversationShortId || "0"),
		conversationType: item.conversationType,
		conversationId: item.conversationId
	} }, ctx.deviceId))["body"]?.getReadIndex?.readIndexList ?? []).map((raw) => ({
		uid: String(raw["uid"] ?? ""),
		readIndex: Number(raw["readIndex"] ?? 0),
		...raw["extra"] != null ? { extra: Number(raw["extra"]) } : {}
	}));
}
/** cmd=2038 batch_get_conversation_participants_readindex:批量查所有成员已读游标（HAR 响应为空 body） */
async function batchReadIndex(ctx, item) {
	return actionResponse(await ctx.transport.sendCookieProto(2038, item.inboxType ?? 1, "/v1/conversation/batch_get_conversation_participants_readindex", { getConversationParticipantsReadIndex: {
		conversationId: item.conversationId,
		conversationShortId: LONG.fromString(item.conversationShortId || "0"),
		getUserReadIndex: 1
	} }, ctx.deviceId), "getConversationParticipantsReadIndex");
}
/** cmd=2001 get_min_index:按会话查各成员最小同步游标（增量拉取起点） */
async function getMinIndex(ctx, item) {
	return ((await ctx.transport.sendCookieProto(2001, item.inboxType ?? 0, "/v3/conversation/get_min_index", { getMinIndex: {
		conversationShortId: LONG.fromString(item.conversationShortId || "0"),
		conversationType: item.conversationType,
		conversationId: item.conversationId
	} }, ctx.deviceId))["body"]?.getMinIndex?.minIndexList ?? []).map((raw) => ({
		uid: String(raw["uid"] ?? ""),
		minIndex: Number(raw["minIndex"] ?? 0)
	}));
}
//#endregion
//#region src/message/query.ts
/** cmd=12048 get_user_message:按 uid 消息区间查询（HAR 响应字段全 0，返回原始结构） */
async function getUserMessage(ctx, req = {}) {
	return (await ctx.transport.sendCookieProto(12048, req.inboxType ?? 0, "/v1/message/get_user_message", { getUserMessage: {
		startIndex: LONG.fromString(req.startIndex ?? "0"),
		messageType: LONG.fromString(req.messageType ?? "0"),
		endIndex: LONG.fromString(req.endIndex ?? "0"),
		cursor: req.cursor ?? ""
	} }, ctx.deviceId))["body"]?.["getUserMessage"] ?? {};
}
/** cmd=2010 client/ack:客户端消息回执（type=500 到达/已读确认，响应仅 envelope 成功帧） */
async function clientAck(ctx, item) {
	return actionResponse(await ctx.transport.sendCookieProto(2010, item.inboxType ?? 0, "/v1/client/ack", { clientAck: {
		serverMessageId: LONG.fromString(item.serverMessageId),
		messageType: item.messageType ?? 500,
		status: item.status ?? 0,
		...item.clientMessageId ? { clientMessageId: LONG.fromString(item.clientMessageId) } : {},
		...item.conversationShortId ? { conversationShortId: LONG.fromString(item.conversationShortId) } : {},
		...item.count != null ? { count: item.count } : {}
	} }, ctx.deviceId));
}
/** cmd=1001 stranger/get_conversation_list:陌生人会话列表（实测服务端限流 409，错因在 statusMsg） */
async function strangerConversations(ctx, req = {}) {
	return actionResponse(await ctx.transport.sendCookieProto(1001, req.inboxType ?? 0, "/v1/stranger/get_conversation_list", { strangerConversationList: {
		cursor: LONG.fromString(String(req.cursor ?? "0")),
		source: req.source ?? 1,
		scene: req.scene ?? 1
	} }, ctx.deviceId));
}
//#endregion
//#region src/live/active.ts
/** active/update:im 活跃心跳上报（登录后打一次即可，成功即静默） */
async function heartbeat(http) {
	const res = await http.json(`${site.edge}${api.activeUpdate}`, { headers: { Referer: site.web } });
	if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
}
/** active/status:批量查 sec 用户在线状态（source 透传，缺省 heartbeat） */
async function onlineStatus(http, secUserIds, source = "heartbeat") {
	const form = new URLSearchParams({
		conv_ids: "[]",
		sec_user_ids: JSON.stringify(secUserIds),
		source
	});
	return ((await http.json(`${site.web}${api.activeStatus}`, {
		method: "POST",
		headers: {
			Referer: site.web,
			"Content-Type": "application/x-www-form-urlencoded"
		},
		body: form.toString()
	})).data?.data ?? []).map((item) => ({
		secUserId: String(item.sec_user_id ?? ""),
		lastActiveTime: Number(item.last_active_time ?? 0)
	}));
}
/** active/config/get:查询在线状态开关（1=开启，我可被对方看到在线） */
async function activeSwitch(http) {
	const res = await http.json(`${site.web}${api.activeConfig}`, { headers: { Referer: site.web } });
	return Number(res.data?.status_switch ?? 0);
}
/** msg_read_switch:标记一批消息已读（会话侧收件箱收到 50013 的依据；source 固定 msg_tab） */
async function readSwitch(http, items) {
	const res = await http.json(`${site.web}${api.readSwitch}`, {
		method: "POST",
		headers: {
			Referer: site.web,
			"Content-Type": "application/json"
		},
		body: JSON.stringify({
			msg_ids: items.map((it) => ({
				msg_id: it.msgId,
				conv_id: it.convId,
				conv_short_id: it.convShortId,
				create_time: it.createTime,
				conv_type: it.convType
			})),
			is_retry: false,
			source: "msg_tab"
		})
	});
	if ((res.data?.msg_ids_resp ?? []).find((r) => Number(r.err_code ?? 0) !== 0)) return err(res.data);
}
//#endregion
//#region src/bot/chat.ts
var Chat = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	history(chatId, opts = {}) {
		return getChatHistory(this.bot.ctx().inbox, {
			...toAddress(chatId),
			...opts
		});
	}
	async strangers() {
		const list = await getStrangerList(this.bot.ctx().inbox);
		this.bot.rememberNicks(list);
		return list;
	}
	/** 会话列表（旧 Cookie 通道，保留备用） */
	list(options = {}) {
		return listConversationsByCookie(this.bot.ctx().inbox, options);
	}
	/** 会话详情（ticket/未读/成员），映射对齐列表会话 */
	info(chatId) {
		return getInfoList(this.bot.ctx().inbox, [toAddress(chatId)]);
	}
	/** 会话成员已读游标（cmd=2000） */
	readIndex(chatId) {
		return getReadIndex(this.bot.ctx().inbox, toAddress(chatId));
	}
	/** 会话成员最小同步游标（cmd=2001，增量拉取起点） */
	minIndex(chatId) {
		return getMinIndex(this.bot.ctx().inbox, toAddress(chatId));
	}
	/** 按 uid 消息区间查询（cmd=12048，语义不完整返回原始结构） */
	userMessageStat(req = {}) {
		return getUserMessage(this.bot.ctx().inbox, req);
	}
	/** 消息回执确认（cmd=2010） */
	ack(chatId, serverMessageId) {
		return clientAck(this.bot.ctx().inbox, {
			serverMessageId,
			conversationShortId: toAddress(chatId).conversationShortId
		});
	}
	/** 陌生人会话列表（服务端限流 409 时 statusMsg 会给出原因） */
	strangerConversations() {
		return strangerConversations(this.bot.ctx().inbox, {});
	}
	/** 将一批入站消息标记已读（会话侧收到 50013 已读回执的依据） */
	readSwitch(chatId, msgs) {
		const addr = toAddress(chatId);
		return readSwitch(this.bot.ctx().http, msgs.filter((m) => m.serverMessageId).map((m) => ({
			msgId: m.serverMessageId,
			convId: addr.conversationId,
			convShortId: addr.conversationShortId,
			createTime: Number(m.createTime ?? 0),
			convType: addr.conversationType
		})));
	}
	/** 删除会话（cmd=603） */
	delete(chatId) {
		return deleteConversation(this.bot.ctx().inbox, toAddress(chatId));
	}
	/** 会话设置：置顶/免打扰/收藏（cmd=921） */
	setting(chatId, input) {
		return setConversationSetting(this.bot.ctx().inbox, toAddress(chatId), input);
	}
	/** 批量查所有成员已读游标（cmd=2038） */
	batchReadIndex(chatId) {
		return batchReadIndex(this.bot.ctx().inbox, toAddress(chatId));
	}
};
//#endregion
//#region src/session/sign/source.ts
/**
* `account_sdk_source_info`：对 JSON 字符串逐字节 XOR 5，再按 JS `toString(16)` 无补零拼成 hex。
*/
function encodeSourceInfo(plain) {
	let out = "";
	for (const ch of plain) out += ((ch.codePointAt(0) ?? 0) ^ 5).toString(16);
	return out;
}
//#endregion
//#region src/session/sign/browser.ts
function encodeBrowserInfo(info) {
	return encodeSourceInfo(JSON.stringify(info));
}
/** 桌面内嵌登录页的 browserInfo 模板（Electron 本地 file:// 渲染；时间戳每次调用刷新） */
function browserInfo(deviceId) {
	return {
		hardwareConcurrency: 8,
		webdriver: false,
		chromedriver: false,
		shelldriver: false,
		plugins: 5,
		permissions: [{
			name: "notifications",
			state: "granted"
		}],
		innerHeight: 484,
		innerWidth: 726,
		outerHeight: 484,
		outerWidth: 726,
		stoargeStatus: {
			indexedDB: {
				idb: "object",
				open: "function",
				indexedDB: "object",
				IDBKeyRange: "function",
				openDatabase: "function",
				isSafari: false,
				hasFetch: false
			},
			localStorage: {
				isSupportLStorage: true,
				size: 1993,
				write: true
			},
			storageQuotaStatus: {
				usage: 0,
				quota: 36104626176,
				isPrivate: false
			}
		},
		webgl: {
			vendor: "Google Inc. (Google)",
			renderer: "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"
		},
		notificationPermission: "granted",
		performance: {
			timeOrigin: Date.now(),
			usedJSHeapSize: 182e5,
			navigationTiming: {
				decodedBodySize: 2527,
				entryType: "navigation",
				initiatorType: "navigation",
				name: `file:///renderer/login/index.html?window=login&channel=0&guid=${deviceId}`,
				renderBlockingStatus: "non-blocking"
			}
		},
		request_host: "",
		request_pathname: "/renderer/login/index.html",
		browser: {
			t: String(Date.now()),
			bit_protocol: "false",
			bit_helper: false
		}
	};
}
//#endregion
//#region src/session/login/codes.ts
/** 登录链路与验证中心的常量、魔法值:协议路径、错误码、状态、验证方式、表单值与验证中心参数统一集中 */
const tag = "login";
/** 轮询节奏与请求超时(协议节奏,勿随意改) */
const time = {
	/** 基准间隔;外层轮数到 60/180 后递增到 mid/max,与官方客户端一致避开频控 */
	poll: 1e3,
	pollMid: 3e3,
	pollMax: 5e3,
	timeout: 12e4,
	upPoll: 3e3,
	upTimeout: 18e4,
	appVerifyWait: 5e3,
	/** 本地验证页等待上限 */
	verify: 3e5,
	/** 验证组件请求超时 */
	fetch: 3e4
};
/** 扫码请求公共参数 */
const qr = {
	needLogo: "false",
	needShort: "false",
	frontier: "true",
	newLogin: "1",
	next: "https://www.douyin.com"
};
const path = {
	qrcode: "/passport/web/get_qrcode/",
	check: "/passport/web/check_qrconnect/",
	send: "/passport/web/send_code/",
	validate: "/passport/web/validate_code/",
	password: "/passport/web/account/verify/",
	pack: "/passport/safe/pack_verify_ways_data/",
	ttwid: "/ttwid/check/"
};
/** 登录链路里需要判断的错误码(与 SDK 的 err 抛错函数区分命名) */
const ec = {
	tooFrequent: 7,
	appVerify: 2046,
	verifyLimit: 3,
	/** 频控退避重试上限:提示「稍后再试」说明是暂时性的,退避后仍有成功机会 */
	frequentLimit: 3
};
const st = {
	new: "new",
	scanned: "scanned",
	confirmed: "confirmed",
	expired: "expired",
	verifying: "verifying",
	verified: "verified"
};
const way = {
	assistSms: "assist_mobile_sms_verify",
	sms: "mobile_sms_verify",
	upSms: "assist_mobile_up_sms_verify",
	password: "pwd_verify",
	/** 内置优先级:安全手机短信 > 绑定手机短信 > 上行短信 > 登录密码 */
	order: [
		"assist_mobile_sms_verify",
		"mobile_sms_verify",
		"assist_mobile_up_sms_verify",
		"pwd_verify"
	]
};
/** Passport 表单固定值 */
const fld = {
	iid: "0",
	mixMode: "1",
	sdk: "1.0.0.428-web",
	copywriting: "qr_connect",
	diversion: "mfa",
	scene: "account_login",
	template: "ato",
	type: "MFA",
	desktopType: "3737",
	webType: "363c",
	smsOk: "success",
	sixDigits: "1",
	defaultSms: "YZ",
	accountFlow: "verify",
	service: "",
	bizKeys: [
		"passport_mfa_retry_tag",
		"std_verify_flow_id",
		"std_verify_scene",
		"std_verify_template",
		"std_verify_token",
		"std_verify_type",
		"std_verify_way"
	]
};
const ck = {
	source: "sdk_source_info",
	msToken: "msToken",
	uid: "uid_tt"
};
const bogus = "jumpbyte-desktop";
/** 重复的用户提示,避免多处硬编码 */
const msg = {
	appVerify: "请前往抖音 App 完成安全验证后继续登录",
	assistSwitch: "已改用辅助手机接收验证码",
	smsOk: "短信验证通过",
	pwdOk: "密码验证通过"
};
/** 验证中心(风控/滑块)协议常量 */
const vc = {
	/** 网页登录场景 aid;桌面 IM 用 im 域 aid */
	webAid: 6383,
	/** VerifyCenter 按这些 code 分发,而非嵌套 MFA 决策里的描述串 */
	codes: [
		1e4,
		2e4,
		3e4,
		4e4
	],
	/** 决策默认场景层级(官方 iframe 由业务初始化传入) */
	scene: "p0",
	/** 官方成功链路 captcha/get 必填业务参数(缺失即 501) */
	repo: "579047",
	h5: "4.0.26",
	extra: { scene: "normal" },
	/** 服务端 fp 只接受 verify_* 字符串 */
	fpPrefix: "verify_",
	/** fp 页面存储键与 Cookie 名 */
	webId: "s_v_web_id",
	/** 决策 verify_from 取值 */
	from: "verify_center",
	captcha: "captcha",
	/** 二次决策标记 */
	level: "secondary",
	/** SecondVerify SDK 版本 */
	sdk: "1.0.29",
	/** vcs 配置接口与请求头标记 */
	setting: "https://vcs.zijieapi.com/vc/setting",
	flag: "1",
	/** 官方验证码组件地址及备用地址 */
	center: "https://lf-rc1.yhgfb-cn-static.com/obj/rc-verifycenter/verifycenter/@latest/index.js",
	centerBackups: ["https://lf-rc2.yhgfb-cn-static.com/obj/rc-verifycenter/verifycenter/@latest/index.js", "https://lf-cdn-tos.bytescm.com/obj/rc-verifycenter/verifycenter/@latest/index.js"]
};
/** 验证页代理允许访问的主机(不含协议) */
const host = {
	im: "imdesktop.douyin.com",
	login: "login.douyin.com",
	web: "www.douyin.com",
	verify: "verify.zijieapi.com",
	vcs: "vcs.zijieapi.com"
};
//#endregion
//#region src/session/login/body.ts
/** Passport 登录请求体组装:check_qrconnect 与 MFA 表单、biz 透传字段。另含签名附加值构造。 */
function qrBody(token) {
	return {
		need_logo: qr.needLogo,
		need_short_url: qr.needShort,
		is_frontier: qr.frontier,
		token,
		is_new_login: qr.newLogin,
		next: qr.next
	};
}
function mfaBody(challenge, verifyWay, extra) {
	const biz = challenge.biz_params ?? {};
	const common = challenge.common_params ?? {};
	const value = (source, key, fallback = "") => {
		const candidate = source[key];
		return candidate == null || candidate === "" ? fallback : String(candidate);
	};
	return {
		mix_mode: fld.mixMode,
		...verifyWay === way.password ? {} : { type: verifyWay === way.sms ? fld.desktopType : fld.webType },
		encrypt_uid: challenge.encrypt_uid ?? "",
		verify_ticket: "",
		copywriting_key: value(common, "copywriting_key", fld.copywriting),
		ies_safety_diversion_tag: value(common, "ies_safety_diversion_tag", fld.diversion),
		new_verify_flow: value(common, "new_verify_flow"),
		std_verify_flow_id: value(biz, "std_verify_flow_id", value(common, "std_verify_flow_id")),
		std_verify_scene: value(biz, "std_verify_scene", fld.scene),
		std_verify_template: value(biz, "std_verify_template", fld.template),
		std_verify_token: value(biz, "std_verify_token", value(common, "std_verify_token")),
		std_verify_type: value(biz, "std_verify_type", fld.type),
		std_verify_way: verifyWay,
		...extra,
		aid: passport.aid,
		new_authn_sdk_version: fld.sdk
	};
}
/** MFA 校验通过后,轮询 check_qrconnect 需要携带的 biz 参数 */
function pickBiz(params) {
	const result = {};
	if (!params) return result;
	for (const key of fld.bizKeys) {
		const value = params[key];
		if (value != null) result[key] = String(value);
	}
	return result;
}
/** account_sdk_source_info:优先 Cookie,缺失时以 browserInfo 模板编码并回写 */
function sdkSourceInfo(http) {
	const stored = http.jar.get(ck.source);
	if (stored) return stored;
	const info = encodeBrowserInfo(browserInfo(http.deviceId));
	http.jar.set(ck.source, info);
	return info;
}
function signExtras(http, bodyWire = "") {
	const extras = {
		userAgent: http.ua,
		appKey: passport.appKey,
		aBogusVariant: bogus,
		bodyWire
	};
	extras.msToken = http.jar.get(ck.msToken) ?? randomMsToken();
	return extras;
}
//#endregion
//#region src/contact/account.ts
/** passport 账号：GET /passport/account/info/v2/，登录态下取当前账号详情（uid/昵称/手机/邮箱） */
/** account/info/v2：passport 签名链路（2.4.12 基础 query + sign + qs），无 body 的明文 GET */
async function accountInfo(http) {
	const { search } = signQuery(passportBaseQuery({
		deviceId: http.deviceId,
		installId: http.installId,
		accountSdkSourceInfo: sdkSourceInfo(http),
		bizTraceId: http.bizTraceId
	}), {}, signExtras(http));
	const url = `${passport.origin}${api.accountInfo}?${search}`;
	const raw = (await http.json(url, { headers: http.passportHeaders(url) })).data.data;
	return {
		userId: String(raw["user_id"] ?? raw["user_id_str"] ?? ""),
		secUserId: String(raw["sec_user_id"] ?? ""),
		...typeof raw["name"] === "string" && raw["name"] ? { name: raw["name"] } : {},
		...typeof raw["screen_name"] === "string" && raw["screen_name"] ? { screenName: raw["screen_name"] } : {},
		...typeof raw["avatar_url"] === "string" && raw["avatar_url"] ? { avatar: raw["avatar_url"] } : {},
		...typeof raw["mobile"] === "string" ? { mobile: raw["mobile"] } : {},
		...typeof raw["email"] === "string" ? { email: raw["email"] } : {},
		...raw["gender"] != null ? { gender: Number(raw["gender"]) } : {},
		...raw["has_password"] != null ? { hasPassword: Number(raw["has_password"]) === 1 } : {},
		...raw["user_create_time"] != null ? { createTime: Number(raw["user_create_time"]) } : {},
		raw
	};
}
/**
* token/beat/web：passport 令牌心跳，长期在线续杯防掉线。
* scene boot=启动首跳、polling=周期轮询；version 为 beat 携带的 SDK 版本（HAR 实证 1.2.13）
*/
async function beatToken(http, scene = "boot") {
	const { search } = signQuery({
		...passportBaseQuery({
			deviceId: http.deviceId,
			installId: http.installId,
			accountSdkSourceInfo: sdkSourceInfo(http),
			bizTraceId: http.bizTraceId,
			extra: { scene }
		}),
		version: ver.beat
	}, {}, signExtras(http));
	const url = `${passport.origin}${api.tokenBeat}?${search}`;
	const res = await http.json(url, { headers: http.passportHeaders(url) });
	if (Number(res.data?.data?.error_code ?? 0) !== 0) return err(res.data);
}
//#endregion
//#region src/bot/user.ts
var User = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	self() {
		return self(this.bot.http());
	}
	/** passport 账号详情（uid/昵称/手机/邮箱，登录态） */
	account() {
		return accountInfo(this.bot.http());
	}
	/** passport 令牌心跳（scene=boot 启动 / polling 周期轮询），续杯防掉线 */
	beatToken(scene = "boot") {
		return beatToken(this.bot.http(), scene);
	}
	/** 批量查用户信息（昵称/头像/签名/关系），按 secUid */
	info(secUids) {
		return userInfo(this.bot.http(), secUids);
	}
	/** 对话场景资料（字段比 profileOther 少） */
	profileScene(secUid) {
		return profileScene(this.bot.http(), secUid);
	}
	/** 完整资料（含地域/年龄等原始字段，raw 透传） */
	profileOther(secUid) {
		return profileOther(this.bot.http(), secUid);
	}
	/** 自己的完整资料 */
	profileSelf() {
		return profileSelf(this.bot.http());
	}
	/** 批量查 sec 用户在线状态 */
	onlineStatus(secUserIds, source) {
		return onlineStatus(this.bot.http(), secUserIds, source);
	}
	/** im 活跃心跳上报（登录后打一次即可） */
	heartbeat() {
		return heartbeat(this.bot.http());
	}
	/** 在线状态开关（1=开启，我可被对方看到在线） */
	activeSwitch() {
		return activeSwitch(this.bot.http());
	}
};
//#endregion
//#region src/bot/sticker.ts
var Sticker = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 表情资源列表；scenes 缺省我的收藏，其他面板场景可自行传参探测 */
	list(options) {
		return stickerList(this.bot.ctx().http, options);
	}
	/** 我的收藏表情（CUSTOM_STICKER_PAGE 面板） */
	favs() {
		return stickerList(this.bot.ctx().http);
	}
	/** 动图/GIF 表情：收藏中带 animate 动图的贴纸 */
	async gifs() {
		const page = await stickerList(this.bot.ctx().http);
		return {
			...page,
			list: page.list.filter((s) => s.animate)
		};
	}
	/** 收藏/取消收藏表情（remove=true 取消） */
	collect(ids, options) {
		return stickerCollect(this.bot.ctx().http, ids, options);
	}
	/** 热门表情分页（cursor+count 翻页） */
	trending(options) {
		return emojiTrending(this.bot.ctx().http, options);
	}
	/** app 能力开关（决策树 + 动效资源包配置） */
	strategy(scenes) {
		return strategyConfig(this.bot.ctx().http, scenes);
	}
	/** 图源 uri 渲染为打码图（分享卡片脱敏用），返回 CDN 直链列表 */
	privacyImage(uri, options) {
		return privacyImage(this.bot.ctx().http, uri, options);
	}
};
//#endregion
//#region src/contact/social.ts
/** bubble/detail_list：按 bubble_id 查气泡详情（need_user_current_bubble 附带当前使用标记） */
async function bubbleDetail(http, bubbleId, options = {}) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("bubble_id", bubbleId);
	params.set("need_user_current_bubble", String(options.needCurrent ?? true));
	const res = await http.json(`${site.web}${api.bubble}?${params}`, { headers: { Referer: site.web } });
	if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
	return (res.data?.bubble_list ?? []).map(bubbleOf);
}
/** spotlight/relation：关注/好友关系列表（默认 100 条，含推荐与真实网络标记） */
async function spotlight(http, options = {}) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("count", String(options.count ?? 100));
	params.set("source", options.source ?? "coldup_full");
	params.set("with_fstatus", "1");
	params.set("max_time", "0");
	params.set("min_time", "0");
	params.set("address_book_access", "1");
	params.set("new_user_login", "0");
	params.set("need_sorted_info", "true");
	params.set("need_network_recommend", "true");
	params.set("need_real_network", "true");
	params.set("need_remove_share_panel", "true");
	const res = await http.json(`${site.web}${api.spotlight}?${params}`, { headers: { Referer: site.web } });
	return {
		users: (res.data?.followings ?? []).map(socialOf),
		hasMore: res.data?.has_more === true,
		maxTime: Number(res.data?.max_time ?? 0),
		minTime: Number(res.data?.min_time ?? 0)
	};
}
/**
* commit/follow/user：关注用户（type=0 关注；响应体为空，只能以 HTTP 状态判定）。
* verifyFp 与设备绑定：verify_<deviceId>，缺设备时不下发
*/
async function followUser(http, userId, secUid, options = {}) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("user_id", userId);
	params.set("secUid", secUid);
	params.set("type", String(options.type ?? 0));
	params.set("tag", options.tag ?? "frienddetail");
	if (http.hasDevice()) params.set("verifyFp", `verify_${http.deviceId}`);
	const res = await http.request(`${site.im}${api.follow}?${params}`, {
		method: "POST",
		headers: { Referer: site.im }
	});
	if (!res.ok) return err(res.data);
}
/** familiar/list：可能认识的人（version_code 特例 21.6.0，与常规版本不同） */
async function familiarList(http, options = {}) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("version_code", "21.6.0");
	params.set("iid", http.installId);
	params.set("cursor", String(options.cursor ?? 0));
	params.set("vcd_count", "0");
	params.set("hotsoon_has_more", "0");
	params.set("only_total", "0");
	params.set("count", String(options.count ?? 100));
	params.set("order_by", "1");
	params.set("need_all_friend", "1");
	params.set("recommend_type", String(options.recommendType ?? 22));
	const res = await http.json(`${site.im}${api.familiar}?${params}`, { headers: { Referer: site.im } });
	if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
	return (res.data?.user_list ?? []).map(socialOf);
}
function bubbleOf(raw) {
	const row = raw;
	const resource = row["resource"];
	const light = urlsOf(resource?.["top_preview_light_url"])?.[0];
	const dark = urlsOf(resource?.["top_preview_dark_url"])?.[0];
	return {
		id: typeof row["bubble_id_str"] === "string" ? row["bubble_id_str"] : String(row["bubble_id"] ?? ""),
		name: typeof row["bubble_name"] === "string" ? row["bubble_name"] : "",
		type: Number(row["bubble_type"] ?? 0),
		source: Number(row["source"] ?? 0),
		...typeof row["description"] === "string" && row["description"] ? { description: row["description"] } : {},
		...light ? { lightPreview: light } : {},
		...dark ? { darkPreview: dark } : {},
		current: row["is_user_current_set"] === true,
		raw: row
	};
}
function socialOf(raw) {
	const row = raw;
	const avatar = urlsOf(row["avatar_thumb"])?.[0] ?? urlsOf(row["avatar_small"])?.[0];
	return {
		uid: String(row["uid"] ?? ""),
		secUid: String(row["sec_uid"] ?? ""),
		nickname: typeof row["nickname"] === "string" ? row["nickname"] : "",
		...avatar ? { avatar } : {},
		...typeof row["signature"] === "string" && row["signature"] ? { signature: row["signature"] } : {},
		...typeof row["unique_id"] === "string" && row["unique_id"] ? { uniqueId: row["unique_id"] } : {},
		followStatus: Number(row["follow_status"] ?? 0),
		followerStatus: Number(row["follower_status"] ?? 0),
		raw: row
	};
}
function urlsOf(value) {
	const list = value?.url_list;
	if (!Array.isArray(list)) return void 0;
	return list.filter((url) => typeof url === "string" && url !== "");
}
//#endregion
//#region src/bot/social.ts
var Social$1 = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 关注/好友关系列表（count+source 可调） */
	spotlight(options) {
		return spotlight(this.bot.ctx().http, options);
	}
	/** 可能认识的人 */
	familiar(options) {
		return familiarList(this.bot.ctx().http, options);
	}
	/** 关注用户（响应体为空，只判 HTTP 状态） */
	follow(userId, secUid, options) {
		return followUser(this.bot.ctx().http, userId, secUid, options);
	}
	/** 气泡详情 */
	bubble(bubbleId, options) {
		return bubbleDetail(this.bot.ctx().http, bubbleId, options);
	}
};
//#endregion
//#region src/session/web.ts
/** webapp 批通道：环境参数 + 指纹 + a_bogus 签名，供网页侧读接口共用 */
/** 抖音 PC 客户端 UA；a_bogus 计算用的 UA 必须与请求头一致，否则签名失效 */
const WEB_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) douyin/8.7.0 Chrome/136.0.7103.59 Electron/36.4.0-rs.33.release.pgo.0 TTElectron/36.4.0-rs.33.release.pgo.0 Safari/537.36 awemePcClient/8.7.0 buildId/495279540 osName/Windows";
/** 与 WEB_UA 匹配的屏参；不传输，只参与本地 a_bogus 计算 */
const SCREEN = "1707|960|1707|1019|1707|960|1707|982|Windows";
/** webapp 批环境参数（HAR 实证；服务端不校验字段顺序） */
const envParams = () => ({
	device_platform: "webapp",
	aid: "6383",
	channel: "channel_pc_web",
	app_name: "aweme",
	format: "json",
	pc_client_type: "2",
	pc_libra_divert: "Windows",
	update_version_code: "807000",
	support_h265: "1",
	support_dash: "1",
	version_code: "170400",
	version_name: "17.4.0",
	cookie_enabled: "true",
	screen_width: "1707",
	screen_height: "960",
	browser_language: "zh-CN",
	browser_platform: "Win32",
	browser_name: "Chrome",
	browser_version: "136.0.7103.59",
	browser_online: "true",
	engine_name: "Blink",
	engine_version: "136.0.7103.59",
	os_name: "Windows",
	os_version: "10",
	cpu_core_num: "16",
	device_memory: "8",
	platform: "PC",
	downlink: "7.15",
	effective_type: "4g",
	round_trip_time: "50"
});
/** webid 不在 Cookie：web_sign_token（JWT）payload.id 即 webid */
function webidOf(http) {
	const payload = http.jar.get("web_sign_token")?.split(".")[1];
	if (!payload) return "";
	try {
		const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
		return data.id ? String(data.id) : "";
	} catch {
		return "";
	}
}
/** 环境参数 + 指纹（verifyFp/fp 同源 s_v_web_id；uifid 用 UIFID） */
function fpParams(http, extra) {
	const verifyFp = http.jar.get("s_v_web_id");
	const params = {
		...envParams(),
		...extra
	};
	const webid = webidOf(http);
	const uifid = http.jar.get("UIFID");
	if (webid) params.webid = webid;
	if (uifid) params.uifid = uifid;
	if (verifyFp) {
		params.verifyFp = verifyFp;
		params.fp = verifyFp;
	}
	params.msToken = http.jar.get("msToken") ?? randomMsToken();
	return params;
}
/** 环境+指纹 query 直接作为 a_bogus 签名输入，签名结果再追加到 URL */
function signed(http, path, opts, body) {
	const query = new URLSearchParams(fpParams(http, opts.params ?? {})).toString();
	const bogus = aBogus({
		userAgent: WEB_UA,
		query,
		body,
		screenFingerprint: SCREEN
	});
	return {
		url: `${opts.origin ?? site.web}${path}?${query}&a_bogus=${encodeURIComponent(bogus)}`,
		headers: {
			"User-Agent": WEB_UA,
			Referer: site.web
		}
	};
}
function webGet(http, path, opts = {}) {
	const { url, headers } = signed(http, path, opts, "");
	return http.json(url, { headers });
}
function webPost(http, path, opts = {}) {
	const wire = new URLSearchParams(opts.body ?? {}).toString();
	const { url, headers } = signed(http, path, opts, wire);
	return http.json(url, {
		method: "POST",
		headers: {
			...headers,
			"Content-Type": "application/x-www-form-urlencoded"
		},
		body: wire
	});
}
//#endregion
//#region src/media/watch.ts
/** danmaku/get_v2：拉取作品某时间段弹幕（start/end 为毫秒偏移窗口，webapp 批走 www-hj） */
async function danmaku(http, itemId, options = {}) {
	return ((await webGet(http, api.danmaku, {
		origin: site.edge,
		params: {
			group_id: options.groupId ?? itemId,
			item_id: itemId,
			start_time: String(options.startTime ?? 0),
			end_time: String(options.endTime ?? 0),
			authentication_token: options.token ?? "",
			duration: String(options.duration ?? 0)
		}
	})).data.danmaku_list ?? []).map(danmakuOf);
}
/** play/progress：上报播放进度（服务端据此续播/记历史） */
async function playProgress(http, itemId, progress, duration) {
	const res = await webPost(http, api.playProgress, { body: {
		item_duration: String(duration),
		item_id: itemId,
		item_progress: String(progress)
	} });
	if (Number(res.data.status_code ?? 0) !== 0) err(res.data);
}
/** series/watch/record：短剧剧集观看记录 */
async function seriesRecord(http, seriesId, itemId, episode) {
	const res = await webGet(http, api.seriesRecord, { params: {
		episode: String(episode),
		series_id: seriesId,
		item_id: itemId
	} });
	if (Number(res.data.status_code ?? 0) !== 0) err(res.data);
}
/** mix/watch/record：合集观看记录（webapp 批走 www-hj，scene 固定 pc_web） */
async function mixRecord(http, mixId, itemId, episode) {
	const res = await webGet(http, api.mixRecord, {
		origin: site.edge,
		params: {
			mix_id: mixId,
			episode: String(episode),
			item_id: itemId,
			scene: "pc_web"
		}
	});
	if (Number(res.data.status_code ?? 0) !== 0) err(res.data);
}
/** history/write：写入观看历史（preItemId 缺省为空表示首次写入） */
async function historyWrite(http, awemeId, options = {}) {
	const res = await webPost(http, api.history, {
		origin: site.edge,
		body: {
			author_id: options.authorId ?? "",
			aweme_id: awemeId,
			pre_item_id: options.preItemId ?? "",
			pre_item_seen: "1"
		}
	});
	if (Number(res.data.status_code ?? res.data.BaseResp?.StatusCode ?? 0) !== 0) err(res.data);
}
/** safetyCheck：批量查作品安全等级（HAR 样本 result 为空；非空结构未实证，原样透传） */
async function safetyCheck(http, itemIds) {
	const items = itemIds.map((itemId) => ({
		item_id: itemId,
		dy_q: "",
		tag: 0,
		potential_risk_level: 0,
		authentication_token: ""
	}));
	const res = await webPost(http, api.safety, { body: {
		item_ids: JSON.stringify(items),
		potential_risk_level: "0",
		refer_string: "recommend"
	} });
	if (Number(res.data.status_code ?? 0) !== 0) err(res.data);
	return res.data.result ?? [];
}
function danmakuOf(raw) {
	const r = raw;
	return {
		id: String(r["danmaku_id"] ?? ""),
		itemId: String(r["item_id"] ?? ""),
		userId: String(r["user_id"] ?? ""),
		offsetTime: Number(r["offset_time"] ?? 0),
		text: typeof r["text"] === "string" ? r["text"] : "",
		diggCount: Number(r["digg_count"] ?? 0),
		showDigg: r["show_digg"] === true
	};
}
//#endregion
//#region src/bot/watch.ts
var Watch = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 拉取作品弹幕（startTime/endTime 毫秒偏移窗口） */
	danmaku(itemId, options) {
		return danmaku(this.bot.ctx().http, itemId, options);
	}
	/** 上报播放进度 */
	progress(itemId, progress, duration) {
		return playProgress(this.bot.ctx().http, itemId, progress, duration);
	}
	/** 短剧剧集观看记录 */
	series(seriesId, itemId, episode) {
		return seriesRecord(this.bot.ctx().http, seriesId, itemId, episode);
	}
	/** 合集观看记录 */
	mix(mixId, itemId, episode) {
		return mixRecord(this.bot.ctx().http, mixId, itemId, episode);
	}
	/** 写入观看历史 */
	history(awemeId, options) {
		return historyWrite(this.bot.ctx().http, awemeId, options);
	}
	/** 批量查作品安全等级 */
	safety(itemIds) {
		return safetyCheck(this.bot.ctx().http, itemIds);
	}
};
//#endregion
//#region src/notice/notify.ts
/** notice/count：各通知分组未读数（登录后轮询红点用） */
async function noticeCount(http) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("is_new_notice", "1");
	params.set("need_social_count", "1");
	const res = await http.json(`${site.im}${api.noticeCount}?${params}`, { headers: { Referer: site.im } });
	if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
	return (res.data?.notice_count ?? []).map(countOf);
}
/** notice/：通知列表（缺省互动分组 401；isMarkRead 默认拉取即标记已读，响应体 v2 优先） */
async function noticeList(http, options = {}) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("address_book_access", "1");
	params.set("appTheme", "light");
	params.set("count", String(options.count ?? 20));
	params.set("gps_access", "0");
	params.set("is_mark_read", options.markRead === false ? "0" : "1");
	params.set("is_new_notice", "1");
	params.set("max_time", String(options.maxTime ?? 0));
	params.set("min_time", String(options.minTime ?? 1));
	params.set("notice_group", String(options.group ?? 401));
	params.set("top_group", "0");
	params.set("user_avatar_shrink", "144_144");
	params.set("video_cover_shrink", "192_192");
	const res = await http.json(`${site.im}${api.notice}?${params}`, { headers: { Referer: site.im } });
	if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
	const v2 = res.data?.notice_list_v2 ?? [];
	return {
		list: (v2.length > 0 ? v2 : res.data?.notice_list ?? []).map(noticeOf),
		hasMore: Number(res.data?.has_more ?? 0) === 1 || res.data?.has_more === true,
		maxTime: Number(res.data?.max_time ?? 0),
		minTime: Number(res.data?.min_time ?? 0)
	};
}
function countOf(raw) {
	const r = raw;
	return {
		group: Number(r["group"] ?? 0),
		count: Number(r["count"] ?? 0),
		dotCount: Number(r["dot_count"] ?? 0),
		latestTime: Number(r["latest_time"] ?? 0),
		showType: Number(r["show_type"] ?? 0),
		interactiveShowType: Number(r["interactive_show_type"] ?? 0)
	};
}
function noticeOf(raw) {
	const r = raw;
	return {
		nid: String(r["nid"] ?? ""),
		type: Number(r["type"] ?? 0),
		createTime: Number(r["create_time"] ?? 0),
		raw: r
	};
}
//#endregion
//#region src/bot/notice.ts
var Notice$1 = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 通知分组未读数（红点轮询用） */
	count() {
		return noticeCount(this.bot.ctx().http);
	}
	/** 通知列表（缺省互动分组 401；markRead=false 拉取不标记已读） */
	list(options) {
		return noticeList(this.bot.ctx().http, options);
	}
};
//#endregion
//#region src/notice/setting.ts
/** im/desktop/setting/get：桌面消息提醒设置（无端点参数） */
async function desktopSetting(http) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	const res = await http.json(`${site.im}${api.desktopSetting}?${params}`, { headers: { Referer: site.im } });
	if (Number(res.data?.base_resp?.status_code ?? 0) !== 0) return err(res.data);
	return {
		messageAlert: Number(res.data.message_alert_switch ?? 0),
		showMessageDetail: Number(res.data.show_message_detail_swtich ?? 0)
	};
}
/** user/settings：账号综合设置（频率控制 + 本地缓存标记随请求下发） */
async function userSettings(http) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("is_fetch_frequency_control", "true");
	params.set("has_local_cache", "false");
	params.set("request_source", "settings_page");
	const res = await http.json(`${site.web}${api.userSettings}?${params}`, { headers: { Referer: site.web } });
	if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
	return {
		chatSet: Number(res.data["chat_set"] ?? 0),
		teenMode: Number(res.data["teen_mode"] ?? 0),
		isMinor: res.data["is_minor"] === true,
		...typeof res.data["settings_version"] === "string" && res.data["settings_version"] ? { settingsVersion: res.data["settings_version"] } : {},
		raw: res.data
	};
}
/** compliance/settings：合规/青少年模式设置（called_token 固定 impc_on_login） */
async function complianceSetting(http) {
	const params = fingerprintParams(http.deviceId, http.guid);
	params.set("iid", http.installId);
	params.set("called_token", "impc_on_login");
	params.set("called_token_extra_info_flag", String(Date.now()));
	params.set("teen_mode_status", "0");
	params.set("ftc_child_mode", "0");
	const res = await http.json(`${site.im}${api.compliance}?${params}`, { headers: { Referer: site.im } });
	if (Number(res.data?.status_code ?? 0) !== 0) return err(res.data);
	return {
		minorControlType: Number(res.data["minor_control_type"] ?? 0),
		isMinor: res.data["is_minor"] === true,
		teenMode: Number(res.data["teen_mode"] ?? 0),
		raw: res.data
	};
}
//#endregion
//#region src/bot/setting.ts
var Setting = class {
	bot;
	constructor(bot) {
		this.bot = bot;
	}
	/** 桌面消息提醒设置 */
	desktop() {
		return desktopSetting(this.bot.ctx().http);
	}
	/** 账号综合设置（私密等级/青少年模式，raw 透传全量字段） */
	account() {
		return userSettings(this.bot.ctx().http);
	}
	/** 合规/青少年模式设置 */
	compliance() {
		return complianceSetting(this.bot.ctx().http);
	}
};
//#endregion
//#region src/app/sign/hash.ts
function md5Hex(data) {
	return createHash("md5").update(data).digest("hex");
}
function ssStub(body) {
	return md5Hex(body).toUpperCase();
}
//#endregion
//#region src/app/codec.ts
/** 传输层编解码：zstd 压缩、按头/魔数解压、验证码 XOR */
const z = zlib;
/** x-bd-content-encoding: zstd */
function zstdCompress(buf) {
	if (!z.zstdCompressSync) throw new Error("当前 Node 不支持 zstd，需要 >= 22.15");
	return z.zstdCompressSync(buf);
}
function hasZstd(b) {
	return b.length >= 4 && b[0] === 40 && b[1] === 181 && b[2] === 47 && b[3] === 253;
}
/** 按 content-encoding 或魔数解压（zstd / gzip / deflate / br） */
function decompress(buf, contentEncoding = "") {
	const ce = contentEncoding.toLowerCase();
	if (hasZstd(buf)) return z.zstdDecompressSync(buf);
	if (ce === "zstd") return z.zstdDecompressSync(buf);
	if (ce === "br") return zlib.brotliDecompressSync(buf);
	if (ce === "gzip" || ce === "deflate") return zlib.gunzipSync(buf);
	return buf;
}
/** WS 推送 payload_encoding=__lz4：帧内不带原始长度，按需扩容解 raw block */
function lz4(src) {
	if (src.length === 0) return Buffer.alloc(0);
	let out = Buffer.alloc(Math.max(256, src.length * 3));
	let ip = 0;
	let op = 0;
	const ensure = (n) => {
		if (op + n <= out.length) return;
		const next = Buffer.alloc(Math.max(op + n, out.length * 2));
		out.copy(next, 0, 0, op);
		out = next;
	};
	while (ip < src.length) {
		const token = src[ip++];
		let len = token >>> 4;
		if (len === 15) {
			let ext = 0;
			do {
				if (ip >= src.length) throw new Error("lz4 数据截断");
				ext = src[ip++];
				len += ext;
			} while (ext === 255);
		}
		if (ip + len > src.length) throw new Error("lz4 字面量截断");
		ensure(len);
		out.set(src.subarray(ip, ip + len), op);
		ip += len;
		op += len;
		if (ip >= src.length) break;
		if (ip + 2 > src.length) throw new Error("lz4 偏移截断");
		const offset = src[ip] | src[ip + 1] << 8;
		ip += 2;
		if (offset === 0 || offset > op) throw new Error("lz4 偏移越界");
		let match = token & 15;
		if (match === 15) {
			let ext = 0;
			do {
				if (ip >= src.length) throw new Error("lz4 数据截断");
				ext = src[ip++];
				match += ext;
			} while (ext === 255);
		}
		match += 4;
		ensure(match);
		let from = op - offset;
		for (let i = 0; i < match; i++) out[op++] = out[from++];
	}
	return out.subarray(0, op);
}
/** 真机行为：验证码先 XOR 0x05 再小写 hex */
function xor5Hex(s) {
	const b = Buffer.from(s, "utf8");
	for (let i = 0; i < b.length; i++) b[i] ^= 5;
	return b.toString("hex");
}
//#endregion
//#region src/app/frame.ts
/**
* App Frontier 帧编解码：结构对齐 com.bytedance.common.wschannel.model.Frame，
* 与 web 的 pbbp2 不是同一套封装。64 位字段保持 bigint，回执要原样带回。
*/
const text = new TextDecoder();
function varint(data, c) {
	let value = 0n;
	let shift = 0n;
	while (c.pos < data.length) {
		const byte = data[c.pos++];
		value |= BigInt(byte & 127) << shift;
		if ((byte & 128) === 0) return value;
		shift += 7n;
	}
	throw new Error("帧 varint 截断");
}
function chunk(data, c) {
	const len = Number(varint(data, c));
	const end = c.pos + len;
	if (end > data.length) throw new Error("帧长度截断");
	const out = data.subarray(c.pos, end);
	c.pos = end;
	return out;
}
/** ExtendedEntry { 1: key, 2: value } */
function entry$1(data) {
	const c = { pos: 0 };
	let key = "";
	let value = "";
	while (c.pos < data.length) {
		const tag = Number(varint(data, c));
		const raw = chunk(data, c);
		if (tag >>> 3 === 1) key = text.decode(raw);
		else if (tag >>> 3 === 2) value = text.decode(raw);
	}
	return key ? [key, value] : null;
}
function decodeFrame(data) {
	const frame = {
		seqid: 0n,
		logid: 0n,
		service: 0,
		method: 0,
		headers: {},
		encoding: "",
		payload: Buffer.alloc(0),
		logidnew: ""
	};
	const c = { pos: 0 };
	try {
		while (c.pos < data.length) {
			const tag = Number(varint(data, c));
			const field = tag >>> 3;
			const wire = tag & 7;
			if (wire === 0) {
				const value = varint(data, c);
				if (field === 1) frame.seqid = value;
				else if (field === 2) frame.logid = value;
				else if (field === 3) frame.service = Number(value);
				else if (field === 4) frame.method = Number(value);
			} else if (wire === 2) {
				const raw = chunk(data, c);
				if (field === 5) {
					const item = entry$1(raw);
					if (item) frame.headers[item[0]] = item[1];
				} else if (field === 6) frame.encoding = text.decode(raw);
				else if (field === 8) frame.payload = Buffer.from(raw);
				else if (field === 9) frame.logidnew = text.decode(raw);
			} else if (wire === 1) c.pos += 8;
			else if (wire === 5) c.pos += 4;
			else return null;
			if (c.pos > data.length) return null;
		}
	} catch {
		return null;
	}
	return frame;
}
/** need_ack=1 的回执帧：复制序号与 service/method，只带 ack 头 */
function ackFrame(frame) {
	if (frame.headers.need_ack !== "1") return null;
	const headers = [
		kv(5, "is_ack", "1"),
		kv(5, "ack_id", frame.logidnew),
		kv(5, "ack_code", "0")
	];
	const msgId = frame.headers.x_frontier_msgid;
	if (msgId) headers.push(kv(5, "x_frontier_msgid", msgId));
	return Buffer.concat([
		fieldVarint$1(1, frame.seqid),
		fieldVarint$1(2, frame.logid),
		fieldVarint$1(3, frame.service),
		fieldVarint$1(4, frame.method),
		...headers,
		fieldStringValue(9, frame.logidnew)
	]);
}
//#endregion
//#region src/app/conf.ts
/** 40.5.0 真机抓包默认值（清除数据全新安装的注册报文） */
const DEV = {
	aid: 1128,
	appName: "aweme",
	packageName: "com.ss.android.ugc.aweme",
	versionCode: 400500,
	versionName: "40.5.0",
	manifestVersionCode: 400501,
	updateVersionCode: 40509900,
	devicePlatform: "android",
	os: "android",
	osApi: 37,
	osVersion: "17",
	build: "CP2A.260605.016",
	romVersion: "PLC110_17.0.0.100(CN01)",
	resolution: "1272*2603",
	dpi: 560,
	deviceType: "PLC110",
	deviceBrand: "OnePlus",
	cpuSupport64: "true",
	hostAbi: "arm64-v8a",
	channel: "huawei_1128_64",
	ac: "wifi",
	mccMnc: "46011",
	ssmix: "a",
	appTheme: "light"
};
/** Android App UA（Cronet 版本与 40.5.0 抓包一致） */
function ua(dev) {
	return `com.ss.android.ugc.aweme/${dev.manifestVersionCode} (Linux; U; Android ${dev.osVersion}; zh_CN; ${dev.deviceType}; Build/${dev.build}; Cronet/TTNetVersion:295fdb87 2026-08-31 QuicVersion:462f352c 2026-08-31)`;
}
/** 账户面板参数：只有 account/info、login_device/list、token/beat 这类接口带，登录接口带上会被判 7 */
const PANEL = [
	["sec_sdk_version", 67765248],
	["ttnet_sdk_version", "4.2.301.9-douyin"],
	["auth_sdk_version", "4.7.7-rc.23"],
	["account_app_language", "zh"],
	["verify_sdk_version", "4.2.1.cn"],
	["multi_login", 1],
	["account_sdk_source", "app"],
	["passport_support_flow", "choose_account,captcha,real_name_check,verify"]
];
/** passport 登录类接口公共 query（真机 44 项，顺序按抓包） */
function passportQuery(dev, ids, extra = {}) {
	const q = new URLSearchParams();
	const base = [
		["passport-sdk-version", 60755],
		["request_from_account_sdk", 1],
		["is_from_ttaccountsdk", 1],
		["language", "zh"],
		["aid", dev.aid],
		["app_name", dev.appName],
		["version_code", dev.versionCode],
		["version_name", dev.versionName],
		["manifest_version_code", dev.manifestVersionCode],
		["update_version_code", dev.updateVersionCode],
		["device_platform", dev.devicePlatform],
		["os", dev.os],
		["os_api", dev.osApi],
		["os_version", dev.osVersion],
		["ssmix", dev.ssmix],
		["channel", dev.channel],
		["ac", dev.ac],
		["mcc_mnc", dev.mccMnc],
		["resolution", dev.resolution],
		["dpi", dev.dpi],
		["device_type", dev.deviceType],
		["device_brand", dev.deviceBrand],
		["cpu_support64", dev.cpuSupport64],
		["host_abi", dev.hostAbi],
		["package", dev.packageName],
		["appTheme", dev.appTheme],
		["use_store_region_cookie", 1]
	];
	for (const [k, v] of base) q.append(k, String(v));
	idQuery(q, ids);
	for (const [k, v] of Object.entries(extra)) q.set(k, String(v));
	return q;
}
/** IM / 通用 API 公共 query（缺字段或身份不一致会返回 3105） */
function socialQuery(dev, ids, extra = {}) {
	const q = new URLSearchParams();
	const base = [
		["ac", dev.ac],
		["channel", dev.channel],
		["aid", dev.aid],
		["app_name", dev.appName],
		["version_code", dev.versionCode],
		["version_name", dev.versionName],
		["device_platform", dev.devicePlatform],
		["os", dev.os],
		["ssmix", dev.ssmix],
		["device_type", dev.deviceType],
		["device_brand", dev.deviceBrand],
		["language", "zh"],
		["os_api", dev.osApi],
		["os_version", dev.osVersion],
		["manifest_version_code", dev.manifestVersionCode],
		["resolution", dev.resolution],
		["dpi", dev.dpi],
		["update_version_code", dev.updateVersionCode],
		["package", dev.packageName],
		["mcc_mnc", dev.mccMnc],
		["first_launch_timestamp", ids.first_install ?? ""],
		["last_deeplink_update_version_code", 0],
		["cpu_support64", dev.cpuSupport64],
		["host_abi", dev.hostAbi],
		["is_guest_mode", 0],
		["app_type", "normal"],
		["minor_status", 0],
		["appTheme", dev.appTheme],
		["is_preinstall", 0],
		["need_personal_recommend", 1],
		["is_android_pad", 0],
		["is_android_fold", 0]
	];
	for (const [k, v] of base) if (String(v) !== "") q.append(k, String(v));
	idQuery(q, ids);
	for (const [k, v] of Object.entries(extra)) q.set(k, String(v));
	return q;
}
function idQuery(q, ids) {
	const pairs = [
		["device_id", ids.device_id],
		["iid", ids.iid],
		["cdid", ids.cdid],
		["klink_egdi", ids.klink_egdi]
	];
	for (const [k, v] of pairs) if (v) q.append(k, v);
}
/** 账户面板接口：在登录 query 上追加面板参数，scene 真机取 normal */
function panelQuery(q, scene = "normal") {
	const out = new URLSearchParams(q);
	for (const [k, v] of PANEL) out.append(k, String(v));
	out.append("is_from_iesaccountsaas", "1");
	out.append("scene", scene);
	return out;
}
function nowTime() {
	const ms = Date.now();
	return {
		ts: Math.floor(ms / 1e3),
		rticket: ms
	};
}
/** 重写动态时间参数，避免重复 */
function buildUrl(host, path, params, t = {}) {
	const q = new URLSearchParams(params);
	for (const k of ["_rticket", "ts"]) q.delete(k);
	const { ts, rticket } = {
		...nowTime(),
		...t
	};
	q.append("_rticket", String(rticket));
	q.append("ts", String(ts));
	return `https://${host}${path}?${q.toString()}`;
}
//#endregion
//#region src/app/link.ts
/** App Frontier 握手：URL 查询与请求头（X-Tt-Token 鉴权，独立于 web Cookie 通道） */
/** WsUrlHelper 的默认地址：私有协议未开启时真机走这里 */
const ws = {
	host: "wss://frontier-aweme.snssdk.com/ws/v2",
	fpid: "9"
};
/** ChannelInfo 的固定查询项；extra 在真机上被内联进 query */
const extra = [
	["ne", "1"],
	["ping-interval", "30"],
	["ttnet_heartbeat_interval", "30"],
	["is_background", "0"],
	["ttnet_ignore_offline", "1"],
	["ws_connect_protocol", "0"],
	["qos_level", "2"]
];
/** access_key = md5(fpid + appKey + device_id + salt)，大小写不敏感但真机输出小写 */
function wsUrl(dev, ids) {
	const q = new URLSearchParams();
	q.set("fpid", ws.fpid);
	q.set("sdk_version", "2");
	q.set("platform", "0");
	q.set("version_code", String(dev.versionCode));
	q.set("aid", String(dev.aid));
	q.set("device_id", ids.device_id);
	q.set("iid", ids.iid);
	q.set("private_protocol_enable", "false");
	q.set("transport_mode", "0");
	q.set("disable_fallback_websocket", "false");
	for (const [k, v] of extra) q.set(k, v);
	q.set("access_key", createHash("md5").update(`${ws.fpid}${cmd.appKey}${ids.device_id}${cmd.salt}`).digest("hex"));
	return `${ws.host}?${q}`;
}
/** 握手头：TTTokenManager 的 token 头 + IM 身份标识，缺 token 时服务端按未登录处理 */
function wsHeaders(dev, auth) {
	const h = {
		"User-Agent": ua(dev),
		"x-support-ack": "1"
	};
	const cookie = auth.cookie();
	if (cookie) h.Cookie = cookie;
	const token = auth.tokens["x-tt-token"];
	if (token) h["X-Tt-Token"] = token;
	const supplement = auth.tokens["x-tt-token-supplement"];
	if (supplement) h["X-Tt-Token-Supplement"] = supplement;
	const uid = auth.jar.get("uid");
	if (uid) {
		h["x-tt-e-k"] = `${uid}+IM`;
		h["x-tt-encrypt-debug"] = "1";
	}
	return h;
}
//#endregion
//#region src/app/ws.ts
/** App 原生 Frontier 长连接：token 握手、30s 心跳、帧回执与指数退避重连 */
/** 30s 与握手 query 的 ping-interval 一致，过密会被服务端断开 */
const BEAT = 3e4;
/** ws 可能把分片合并成数组，这里统一成连续字节 */
function bytes$1(data) {
	if (Buffer.isBuffer(data)) return data;
	if (Array.isArray(data)) return Buffer.concat(data);
	return Buffer.from(data);
}
function delay(attempt) {
	return Math.min(3e4, 1e3 * 2 ** Math.max(0, attempt - 1));
}
/** 不打印日志：重连与关闭全部通过回调交给上层 */
var Ws = class {
	opts;
	socket;
	heartbeat;
	timer;
	task;
	attempt = 0;
	stopped = true;
	opened = false;
	constructor(opts) {
		this.opts = opts;
	}
	get connected() {
		return this.socket?.readyState === WebSocket.OPEN;
	}
	connect() {
		if (this.connected) return Promise.resolve();
		if (this.task) return this.task;
		this.stopped = false;
		const task = this.open();
		this.task = task;
		task.then(() => this.release(task), () => this.release(task));
		return task;
	}
	close() {
		this.stopped = true;
		this.opened = false;
		this.attempt = 0;
		if (this.timer) clearTimeout(this.timer);
		delete this.timer;
		this.stopBeat();
		this.socket?.close();
		delete this.socket;
	}
	open() {
		return new Promise((resolve, reject) => {
			const socket = new WebSocket(wsUrl(this.opts.dev, this.opts.ids), ["pbbp"], {
				headers: wsHeaders(this.opts.dev, this.opts.auth),
				handshakeTimeout: 3e4
			});
			this.socket = socket;
			let done = false;
			let isOpen = false;
			const finish = (error) => {
				if (done) return;
				done = true;
				if (error) reject(error);
				else resolve();
			};
			socket.once("error", finish);
			socket.on("error", () => {});
			socket.once("unexpected-response", (_req, res) => {
				res.resume();
			});
			socket.once("open", () => {
				if (this.stopped) {
					socket.close();
					finish();
					return;
				}
				isOpen = true;
				socket.off("error", finish);
				finish();
				this.attempt = 0;
				this.opened = true;
				this.beat(socket);
			});
			socket.on("message", (data) => {
				const frame = decodeFrame(bytes$1(data));
				if (!frame) return;
				const ack = ackFrame(frame);
				if (ack && socket.readyState === WebSocket.OPEN) socket.send(ack);
				this.opts.onFrame(frame);
			});
			socket.on("close", (code, reason) => {
				this.stopBeat();
				if (this.socket === socket) delete this.socket;
				const text = reason.toString();
				if (!isOpen) finish(new SdkError({
					code,
					reason: text
				}));
				this.opts.onClose?.({
					code,
					reason: text
				});
				if (!this.stopped && this.opened) this.schedule(code, text);
			});
		});
	}
	schedule(code, reason) {
		if (this.stopped || this.timer) return;
		const attempt = ++this.attempt;
		const delayMs = delay(attempt);
		const event = {
			attempt,
			delayMs
		};
		if (code != null) event.code = code;
		if (reason) event.reason = reason;
		this.opts.onReconnecting?.(event);
		this.timer = setTimeout(() => {
			delete this.timer;
			if (this.stopped) return;
			this.open().catch(() => this.schedule());
		}, delayMs);
	}
	beat(socket) {
		this.heartbeat = setInterval(() => {
			if (socket.readyState === WebSocket.OPEN) socket.ping();
		}, BEAT);
	}
	release(task) {
		if (this.task === task) delete this.task;
	}
	stopBeat() {
		if (this.heartbeat) clearInterval(this.heartbeat);
		delete this.heartbeat;
	}
};
//#endregion
//#region src/app/recv.ts
/** App 推送分发：只处理 IM 服务帧，事件语义与 web 通道一致，但传输完全独立 */
/** IM SDK 只认这两个 service；33554856 是 App 侧的扩展通道 */
const SERVICES = /* @__PURE__ */ new Set([5, 33554856]);
/** 系统消息类型：常由本机触发，需先于自发过滤分流为 notice */
const NOTICE_TYPES = /* @__PURE__ */ new Set([1001, 50011]);
var Recv = class extends Emitter {
	ws;
	auth;
	log;
	selfMessage;
	/** 高位信令先于自发过滤：发送者常为本机，但语义是对端/会话视角 */
	signals = /* @__PURE__ */ new Map([
		[50001, (push) => {
			const e = toStatusEvent(push);
			if (e) this.emit("status", e);
		}],
		[50013, (push) => {
			const e = toReadEvent(push);
			if (e) this.emit("read", e);
		}],
		[50018, (push) => {
			const e = toVoipCall(push);
			if (e) this.emit("voip", e);
		}]
	]);
	constructor(opts) {
		super();
		this.auth = opts.auth;
		this.log = opts.log;
		this.selfMessage = opts.selfMessage ?? false;
		this.ws = new Ws({
			dev: opts.dev,
			ids: opts.ids,
			auth: opts.auth,
			onFrame: (frame) => this.frame(frame),
			onReconnecting: (event) => this.emit("reconnecting", event),
			onClose: (event) => this.emit("close", event)
		});
	}
	get connected() {
		return this.ws.connected;
	}
	start() {
		return this.ws.connect();
	}
	stop() {
		this.ws.close();
	}
	/** 一帧内可能包含多类推送：先信号与通知，再普通消息 */
	frame(frame) {
		if (!SERVICES.has(frame.service) || frame.method !== 1) return;
		try {
			const payload = frame.encoding === "__lz4" ? lz4(frame.payload) : frame.payload;
			for (const notice of extractAndroidNotices(payload)) this.route(notice);
			for (const reaction of extractReactions(payload)) this.emit("notice", reaction);
			for (const push of extractAndroidPushes(payload)) this.dispatch(push);
		} catch (error) {
			this.log.warn(`App 推送解析失败：${String(error)}`);
		}
	}
	dispatch(push) {
		const signal = this.signals.get(push.messageType);
		if (signal) {
			signal(push);
			return;
		}
		if (push.editCount != null || push.editInfo) {
			this.emit("message:edited", toInboundMessage(push));
			return;
		}
		if (NOTICE_TYPES.has(push.messageType)) {
			const event = noticeFromPush(push);
			if (event) {
				this.route(event);
				return;
			}
		}
		if (push.messageType >= 5e4 && !push.isThreadRoot) return;
		if (push.senderUid === this.uid() && !this.selfMessage) return;
		const event = push.isThreadRoot ? void 0 : noticeFromPush(push);
		if (event) {
			this.route(event);
			return;
		}
		this.emit("message", toInboundMessage(push));
	}
	/** uid 在登录后才写入 jar，连接建立前不能缓存 */
	uid() {
		return this.auth.jar.get("uid") ?? "";
	}
	/** 好友申请/入群申请走 request，其余通知走 notice */
	route(event) {
		if (event.type === "friend.request" || event.type === "group.join-request") this.emit("request", event);
		else this.emit("notice", event);
	}
};
//#endregion
//#region src/app/ids.ts
/** 设备标识的生成与合并：缺字段才新生成，避免每次注册漂移出新 device_id */
function hex16() {
	return randomBytes(8).toString("hex");
}
/** 合并已有标识并补全本地随机字段；服务端字段（device_id 等）保持为空直到注册 */
function fill(base = {}) {
	const now = Math.floor(Date.now() / 1e3);
	return {
		device_id: base.device_id ?? "",
		iid: base.iid ?? "",
		cdid: base.cdid ?? randomUUID(),
		clientudid: base.clientudid ?? randomUUID(),
		openudid: base.openudid ?? hex16(),
		klink_egdi: base.klink_egdi ?? "",
		device_token: base.device_token ?? "",
		req_id: base.req_id ?? randomUUID(),
		oaid: base.oaid ?? "0".repeat(64),
		first_install: base.first_install ?? now - 604800,
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
		source: base.source
	};
}
//#endregion
//#region src/app/auth.ts
/** App 会话：cookie jar + 响应头回带的 token / MFA 票据 */
const TOKENS = [
	"x-tt-token",
	"x-tt-token-supplement",
	"token-tlb-tag",
	"session-tlb-tag"
];
var Auth = class {
	jar;
	tokens = {};
	/** x-tt-passport-verify-portrait 每次会话随机 */
	portrait = `${randomUUID()}.login`;
	traceId = `login_${randomBytes(16).toString("hex")}`;
	lastHeaders = {};
	/** 2046 凭据：服务端靠它把「验证通过」关联到待登录会话 */
	mfaToken = "";
	/** 设备票据，响应头 d-ticket 下发 */
	dTicket = "";
	/** 本次 MFA 实际通过的验证方式（重放时 echo 到 std_verify_way） */
	verifiedWay = "";
	/** ticket-guard 短时票据：boot 响应头下发，业务请求缺它会被判未提供设备证明 */
	sec = "";
	secAt = 0;
	/** odin_tt 有效期约 31s，按同样节奏刷新预热 */
	warmAt = 0;
	constructor(cookie) {
		this.jar = new Jar(cookie);
		this.seed();
	}
	/** 真机 passport 会话的 csrf 由客户端自生成，每个 passport 请求都会带；缺了服务端按系统繁忙兜底 */
	seed() {
		if (this.jar.get("passport_csrf_token")) return;
		const v = randomBytes(16).toString("hex");
		this.jar.merge(`passport_csrf_token=${v}; passport_csrf_token_default=${v}`);
	}
	cookie() {
		return this.jar.header().split("; ").filter((kv) => !kv.startsWith("ticket_guard_has_set_public_key=")).join("; ");
	}
	/** 二维码是独立会话：重新取码前清空上一轮 cookie/token，否则服务端按系统繁忙兜底 */
	reset() {
		this.jar.clear();
		this.seed();
		this.tokens = {};
		this.portrait = `${randomUUID()}.login`;
		this.traceId = `login_${randomBytes(16).toString("hex")}`;
		this.lastHeaders = {};
		this.mfaToken = "";
		this.dTicket = "";
		this.verifiedWay = "";
		this.sec = "";
		this.secAt = 0;
		this.warmAt = 0;
	}
	absorb(setCookie) {
		for (const line of setCookie) this.jar.absorb(line);
	}
	csrf() {
		return this.jar.get("passport_csrf_token");
	}
	get sessionid() {
		const sid = this.jar.get("sessionid");
		return sid && sid !== "undefined" ? sid : void 0;
	}
	take(headers) {
		for (const n of TOKENS) {
			const v = headers[n] ?? headers[n.toLowerCase()];
			if (v) this.tokens[n] = v;
		}
		const mfa = headers["x-tt-passport-mfa-token"];
		if (mfa) this.mfaToken = mfa;
		const dt = headers["d-ticket"] ?? headers["d_ticket"];
		if (dt) this.dTicket = dt;
	}
};
//#endregion
//#region src/app/http.ts
/** 裸 HTTPS 请求：保留头顺序与多条 set-cookie，响应按 content-encoding 解压 */
const debug = createLog({ tag: "http" });
/** APP_DEBUG=1/true 时输出原始报文；按次读取便于运行时开关 */
function trace$1() {
	const v = process.env.APP_DEBUG;
	return v === "1" || v === "true";
}
/** 二进制载荷转 hex，文本截断避免刷爆终端 */
function dump(buf) {
	if (!buf?.length) return "-";
	const text = buf.toString("utf8");
	if (text.includes("�")) return `hex(${buf.length}) ${buf.subarray(0, 512).toString("hex")}${buf.length > 512 ? "…" : ""}`;
	return text.length > 8e3 ? `${text.slice(0, 8e3)}…(${text.length})` : text;
}
function request(opts) {
	const u = new URL(opts.url);
	const method = opts.method ?? "GET";
	const headers = {};
	const seen = /* @__PURE__ */ new Set();
	for (const [k, v] of opts.headers ?? []) {
		const lk = k.toLowerCase();
		if (seen.has(lk)) {
			const cur = headers[lk];
			headers[lk] = Array.isArray(cur) ? [...cur, v] : [String(cur), v];
		} else {
			headers[lk] = v;
			seen.add(lk);
		}
	}
	if (opts.body) headers["content-length"] = String(opts.body.length);
	const at = Date.now();
	if (trace$1()) {
		const head = (opts.headers ?? []).map(([k, v]) => `  ${k}: ${v}`).join("\n");
		debug.info(`→ ${method} ${opts.url}\n${head}\n\n${dump(opts.body)}`);
	}
	return new Promise((resolve, reject) => {
		const req = https.request({
			host: u.hostname,
			port: u.port || 443,
			path: u.pathname + u.search,
			method,
			headers,
			timeout: opts.timeoutMs ?? 3e4
		}, (res) => {
			const chunks = [];
			res.on("data", (c) => chunks.push(c));
			res.on("end", () => {
				const raw = Buffer.concat(chunks);
				const hdrs = {};
				const setCookie = [];
				for (const [k, v] of Object.entries(res.headers)) {
					if (v === void 0) continue;
					const lk = k.toLowerCase();
					if (lk === "set-cookie") setCookie.push(...Array.isArray(v) ? v : [v]);
					hdrs[lk] = Array.isArray(v) ? v.join(", ") : String(v);
				}
				let body = raw;
				if (opts.autoDecompress !== false) try {
					body = decompress(raw, hdrs["content-encoding"] ?? "");
				} catch {
					body = raw;
				}
				const text = body.toString("utf8");
				let json;
				try {
					json = JSON.parse(text);
				} catch {
					json = void 0;
				}
				if (trace$1()) {
					const head = Object.entries(hdrs).map(([k, v]) => `  ${k}: ${v}`).join("\n");
					debug.info(`← ${res.statusCode ?? 0} ${method} ${u.pathname}${u.search} (${Date.now() - at}ms)\n${head}\n\n${dump(body)}`);
				}
				resolve({
					status: res.statusCode ?? 0,
					headers: hdrs,
					setCookie,
					body,
					text,
					json
				});
			});
		});
		req.on("timeout", () => req.destroy(/* @__PURE__ */ new Error("请求超时")));
		req.on("error", (error) => {
			if (trace$1()) debug.error(`✗ ${method} ${opts.url} (${Date.now() - at}ms) ${error.message}`);
			reject(error);
		});
		if (opts.body) req.write(opts.body);
		req.end();
	});
}
//#endregion
//#region src/app/crypt.ts
/** passport 请求体加密信封（native ttEncrypt）：74 63 05 10 + 32B keyStream + AES-128-CBC 密文 */
const HEAD = Buffer.from([
	116,
	99,
	5,
	16,
	0,
	0
]);
const ORD = Buffer.from("4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58", "hex");
/** AES key = SHA512(SHA512(keyStream) + ORD)[0:16]，IV = 同结果 [16:32] */
function derive(keyStream) {
	const s = createHash("sha512").update(keyStream).digest();
	const d = createHash("sha512").update(Buffer.concat([s, ORD])).digest();
	return {
		key: d.subarray(0, 16),
		iv: d.subarray(16, 32)
	};
}
function ttEncrypt(payload) {
	const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
	const keyStream = randomBytes(32);
	const { key, iv } = derive(keyStream);
	const c = createCipheriv("aes-128-cbc", key, iv);
	const digest = createHash("sha512").update(body).digest();
	const ct = Buffer.concat([c.update(Buffer.concat([digest, body])), c.final()]);
	return Buffer.concat([
		HEAD,
		keyStream,
		ct
	]);
}
//#endregion
//#region src/app/sign/argus.ts
function argus({ unix }) {
	const ts = (unix ?? Math.floor(Date.now() / 1e3)) >>> 0;
	const out = Buffer.alloc(4);
	out.writeUInt32LE(ts, 0);
	return { "x-argus": out.toString("base64") };
}
//#endregion
//#region src/app/sign/gorgon.ts
const LENGTH = 20;
function table(key) {
	const t = Array.from({ length: 256 }, (_, i) => i);
	let j = 0;
	for (let i = 0; i < 256; i++) {
		j = j + t[i] + key[i & 7] & 255;
		t[i] = t[j];
	}
	return t;
}
function initialize(input, hexZu) {
	const t = hexZu.slice();
	let a = 0;
	let j = 0;
	for (let i = 0; i < input.length; i++) {
		a = a + 1 & 255;
		j = j + t[a] & 255;
		const D = t[j];
		t[a] = D;
		t[j] = D;
		input[i] ^= t[D + D & 255];
	}
	return input;
}
function reverse(num) {
	return (num >> 4 | num << 4) & 255;
}
function rbit(num) {
	let out = 0;
	for (let i = 0; i < 8; i++) out |= (num >> i & 1) << 7 - i;
	return out;
}
function handle(input) {
	for (let i = 0; i < LENGTH; i++) {
		const B = reverse(input[i]);
		const C = input[(i + 1) % LENGTH];
		input[i] = ~(rbit(B ^ C) ^ LENGTH) & 255;
	}
	return input;
}
function hex2(num) {
	return num.toString(16).padStart(2, "0");
}
function gorgon({ query, commonParams, stub, unix, key3, key7 }) {
	const signedQuery = commonParams ? query + (query && !query.endsWith("&") ? "&" : "") + commonParams : query;
	const ts = unix ?? Math.floor(Date.now() / 1e3);
	const key = [
		74,
		4,
		22,
		(key3 ?? Math.floor(Math.random() * 256)) & 255,
		71,
		108,
		4,
		(key7 ?? Math.floor(Math.random() * 8) << 5) & 255
	];
	const bytes = [];
	const pushHex = (hex, n = 4) => {
		for (let i = 0; i < n; i++) bytes.push(parseInt(hex.slice(2 * i, 2 * i + 2), 16));
	};
	pushHex(md5Hex(signedQuery));
	if (stub) pushHex(stub.slice(0, 8));
	else bytes.push(0, 0, 0, 0);
	bytes.push(0, 0, 0, 0);
	bytes.push(0, 4, 10, 4);
	pushHex((ts & 4294967295).toString(16).padStart(8, "0"));
	if (bytes.length !== LENGTH) throw new Error(`gorgon input length ${bytes.length}`);
	const out = handle(initialize(bytes, table(key))).map(hex2).join("");
	return {
		"x-gorgon": `8404${hex2(key[7])}${hex2(key[3])}${hex2(key[1])}${hex2(key[6])}` + out,
		"x-khronos": String(ts)
	};
}
//#endregion
//#region src/app/sign/helios.ts
const MASK64$1 = (1n << 64n) - 1n;
function ror64(x, n) {
	const k = BigInt(n & 63);
	return (x >> k | x << 64n - k) & MASK64$1;
}
function rol64(x, n) {
	const k = BigInt(n & 63);
	return (x << k | x >> 64n - k) & MASK64$1;
}
/** bionic rand()：FreeBSD random(TYPE_3)，播种后丢弃 310 个输出 */
function bionicRand(seed) {
	let s = seed >>> 0;
	if (s === 0) s = 1;
	const st = /* @__PURE__ */ new Uint32Array(31);
	st[0] = s;
	for (let i = 1; i < 31; i++) st[i] = 16807 * st[i - 1] % 2147483647;
	let f = 3;
	let r = 0;
	const step = () => {
		const v = st[f] + st[r] >>> 0;
		st[f] = v;
		f = (f + 1) % 31;
		r = (r + 1) % 31;
		return v >>> 1 & 2147483647;
	};
	for (let i = 0; i < 310; i++) step();
	return step;
}
/** 常量表：md5(LE32(rand1) + aid) 的 hex 当 4×u64 种子，递推 34 项 */
function constantTable(rand1, aid) {
	const head = Buffer.alloc(4);
	head.writeUInt32LE(rand1 >>> 0, 0);
	const hex = createHash("md5").update(Buffer.concat([head, Buffer.from(String(aid))])).digest("hex");
	const raw = Buffer.from(hex, "latin1");
	let s0 = raw.readBigUInt64LE(0);
	let s1 = raw.readBigUInt64LE(8);
	let s2 = raw.readBigUInt64LE(16);
	let s3 = raw.readBigUInt64LE(24);
	const out = [s0];
	for (let i = 0; i < 33; i++) {
		const t = (ror64(s1, 8) + s0 & MASK64$1 ^ BigInt(i)) & MASK64$1;
		const a = (t ^ rol64(s0, 3)) & MASK64$1;
		s0 = a;
		s1 = s2;
		s2 = s3;
		s3 = t;
		out.push(a);
	}
	return out;
}
function mix(r4, r6, consts) {
	for (const c of consts) {
		const t = (c ^ ror64(r6, 8) + r4 & MASK64$1) & MASK64$1;
		r4 = (t ^ rol64(r4, 3)) & MASK64$1;
		r6 = t;
	}
	return [r4, r6];
}
/** 40.5.0 libmetasec_ml.so 内 lid 实测恒定，与设备 ID 无关 */
const DEFAULT_LID = 1588093228;
/** 进程级 rand() 序列：真机 srand 一次后每请求取下一个 */
let seq$1 = null;
function helios({ unix, lid = DEFAULT_LID, aid = 1128, seed, rand1 } = {}) {
	const ts = unix ?? Math.floor(Date.now() / 1e3);
	let r1;
	if (rand1 !== void 0) r1 = rand1 >>> 0;
	else if (seed !== void 0) r1 = bionicRand(seed)();
	else {
		if (!seq$1) seq$1 = bionicRand(Math.floor(Date.now() / 1e3));
		r1 = seq$1();
	}
	const consts = constantTable(r1, aid);
	const buf = Buffer.alloc(32, 6);
	Buffer.from(`${ts}-${lid}-${aid}`, "latin1").copy(buf, 0, 0, Math.min(32, buf.length));
	const w1 = mix(buf.readBigUInt64LE(0), buf.readBigUInt64LE(8), consts);
	const w2 = mix(buf.readBigUInt64LE(16), buf.readBigUInt64LE(24), consts);
	const out = Buffer.alloc(36);
	out.writeUInt32LE(r1 >>> 0, 0);
	[
		w1[0],
		w1[1],
		w2[0],
		w2[1]
	].forEach((v, i) => out.writeBigUInt64LE(v, 4 + i * 8));
	return { "x-helios": out.toString("base64") };
}
//#endregion
//#region src/app/sign/ladon.ts
function ladon({ random }) {
	const out = Buffer.alloc(4);
	if (random && random.length >= 4) Buffer.from(random.subarray(0, 4)).copy(out);
	else out.writeUInt32LE(Math.random() * 4294967296 >>> 0, 0);
	return { "x-ladon": out.toString("base64") };
}
//#endregion
//#region src/app/sign/medusa.ts
/** so 内固定的 16 字节标识块（40.5.0，随版本变化） */
const MEDUSA_TAG = Buffer.from("ddc8bca0b9f6fe29cf365d46d2ee3f3c", "hex");
/** FNV-1a 32 位，用作伪随机流的种子 */
function fnv1a(s) {
	let h = 2166136261;
	for (let i = 0; i < s.length; i++) {
		h ^= s.charCodeAt(i);
		h = Math.imul(h, 16777619) >>> 0;
	}
	return h;
}
function medusa(input = {}) {
	const ts = (input.unix ?? Math.floor(Date.now() / 1e3)) >>> 0;
	const query = input.query ?? "";
	const head = Buffer.alloc(24);
	head.writeUInt32LE(ts, 0);
	MEDUSA_TAG.copy(head, 4);
	(input.random && input.random.length >= 2 ? Buffer.from(input.random.subarray(0, 2)) : randomBytes(2)).copy(head, 20);
	head.writeUInt16BE(1, 22);
	const bodyLen = 812 + Math.min(4, Math.floor(query.length / 64));
	const body = Buffer.alloc(bodyLen);
	let s = fnv1a(`${ts}|${query}|${input.deviceId ?? ""}`);
	for (let i = 0; i < bodyLen; i++) {
		s ^= s << 13;
		s >>>= 0;
		s ^= s >>> 17;
		s ^= s << 5;
		s >>>= 0;
		body[i] = s & 255;
	}
	return { "x-medusa": Buffer.concat([head, body]).toString("base64") };
}
//#endregion
//#region src/app/sign/index.ts
/** 纯算六神签名（无 so / 无抓包依赖）；算法体移植自参考实现，只改导入与命名 */
/** 需要重算的头，套模板时先剔除 */
const SIG_HEADERS = [
	"x-perseus",
	"x-medusa",
	"x-argus",
	"x-gorgon",
	"x-helios",
	"x-ladon",
	"x-khronos"
];
function headerOf(pairs, name) {
	const low = name.toLowerCase();
	for (let i = pairs.length - 1; i >= 0; i--) if (pairs[i][0].toLowerCase() === low) return pairs[i][1];
}
function queryOf(url) {
	try {
		const q = new URL(url).search;
		return q.startsWith("?") ? q.slice(1) : q;
	} catch {
		const i = url.indexOf("?");
		return i < 0 ? "" : url.slice(i + 1);
	}
}
/** 去掉模板里的旧签名头，必须重签 */
function strip$1(pairs) {
	const low = new Set(SIG_HEADERS);
	return pairs.filter(([k]) => !low.has(k.toLowerCase()));
}
function sign$1(input) {
	const query = queryOf(input.url);
	const ts = Math.floor(Date.now() / 1e3);
	const rb = randomBytes(4);
	const stub = headerOf(input.headers, "x-ss-stub") ?? (input.bodyBytes && input.bodyBytes.length > 0 ? ssStub(input.bodyBytes) : typeof input.body === "string" && input.body.length > 0 ? ssStub(input.body) : void 0);
	const headers = {};
	Object.assign(headers, ladon({
		unix: ts,
		random: rb
	}));
	Object.assign(headers, gorgon({
		query,
		commonParams: headerOf(input.headers, "x-common-params-v2"),
		stub,
		unix: ts
	}));
	Object.assign(headers, argus({ unix: ts }));
	Object.assign(headers, helios({
		unix: ts,
		aid: 1128
	}));
	Object.assign(headers, medusa({
		unix: ts,
		query,
		deviceId: input.deviceIds?.deviceId,
		random: rb.subarray(0, 2)
	}));
	return headers;
}
//#endregion
//#region src/asset.ts
/** 内置静态资源定位：源码在 src/、打包在 dist/，两种布局都从包根 assets 取 */
const here = dirname(fileURLToPath(import.meta.url));
/** 资源所在目录；找不到返回空串，供「可选资源」自行降级 */
function findAsset(name) {
	return [resolve(here, "../assets"), resolve(process.cwd(), "assets")].find((dir) => existsSync(join(dir, name))) ?? "";
}
/** 资源所在目录；缺失即抛错，避免 readFile 抛模糊的 ENOENT */
function assetDir(name) {
	const dir = findAsset(name);
	if (!dir) throw new Error(`找不到 assets/${name}`);
	return dir;
}
//#endregion
//#region src/app/so/cpu.ts
const MASK64 = 18446744073709551615n;
const MASK32 = 4294967295n;
/**
* AdvSIMD modified immediate 的通道表：key = cmode*2 + op。
* 值 = [通道位数, imm8 左移位数, MSL 补 1 位数, 是否取反(MVNI)]。
* 语义以 capstone 反汇编核对（cmode 0/2/4/6→32 位，8/a→16 位，c/d→MSL，e→8 位/2D）。
*/
const MOVI_LANES = {
	0: [
		32,
		0,
		0,
		0
	],
	1: [
		32,
		0,
		0,
		1
	],
	4: [
		32,
		8,
		0,
		0
	],
	5: [
		32,
		8,
		0,
		1
	],
	8: [
		32,
		16,
		0,
		0
	],
	9: [
		32,
		16,
		0,
		1
	],
	12: [
		32,
		24,
		0,
		0
	],
	13: [
		32,
		24,
		0,
		1
	],
	16: [
		16,
		0,
		0,
		0
	],
	17: [
		16,
		0,
		0,
		1
	],
	20: [
		16,
		8,
		0,
		0
	],
	21: [
		16,
		8,
		0,
		1
	],
	24: [
		32,
		8,
		8,
		0
	],
	25: [
		32,
		8,
		8,
		1
	],
	26: [
		32,
		16,
		16,
		0
	],
	27: [
		32,
		16,
		16,
		1
	],
	28: [
		8,
		0,
		0,
		0
	],
	29: [
		64,
		56,
		0,
		0
	]
};
/** 指令字 → 分类 id。掩码顺序敏感，必须与 verify_decode.py 一致。 */
function classify(w) {
	const eq = (mask, val) => (w & mask) >>> 0 === val;
	if (w === 3573759839) return 1;
	if (eq(4292870175, 3556769793)) return 2;
	if (eq(4292870175, 3558866944)) return 3;
	if (w === 3573752639 || w === 3573752767 || w === 3573752671 || w === 3573752799) return 4;
	if (w === 3573752063) return 5;
	if (eq(4294967071, 3573752863)) return 6;
	if (eq(4294963231, 3573751839)) return 7;
	if (eq(4294963359, 3573756063)) return 8;
	if (eq(4292870144, 3575644160)) return 9;
	if (eq(4292870144, 3573547008)) return 10;
	if (eq(520093696, 268435456)) return 11;
	if (eq(520093696, 285212672)) return 12;
	if (eq(528482304, 301989888)) return 13;
	if (eq(528482304, 310378496)) return 14;
	if (eq(528482304, 318767104)) return 15;
	if (eq(2139095040, 327155712)) return 16;
	if (eq(4278190096, 1409286144)) return 17;
	if (eq(2113929216, 872415232)) return 18;
	if (eq(2113929216, 905969664)) return 19;
	if (eq(2080374784, 335544320)) return 20;
	if (eq(4294966303, 3592355840)) return 21;
	if (eq(4294966303, 3594452992)) return 22;
	if (eq(4294966303, 3596550144)) return 23;
	if (eq(1073740800, 148896768)) return 24;
	if (eq(1073740800, 144702464)) return 25;
	if (eq(1073740800, 140508160)) return 26;
	if (eq(1073740800, 140475392)) return 86;
	if (eq(1071709184, 134282240)) return 27;
	if (eq(1071709184, 134249472)) return 87;
	if (eq(973078528, 671088640)) return 28;
	if (eq(989855744, 956301312)) return 29;
	if (eq(991954944, 941623296)) return 30;
	if (eq(991955968, 939524096)) return 31;
	if (eq(991955968, 939525120)) return 32;
	if (eq(991955968, 939527168)) return 33;
	if (eq(989855744, 402653184)) return 34;
	if (eq(522190848, 184549376)) return 35;
	if (eq(522190848, 186646528)) return 36;
	if (eq(520093696, 167772160)) return 37;
	if (eq(534773760, 436207616)) return 38;
	if (eq(534773760, 444596224)) return 39;
	if (eq(534775808, 440401920)) return 40;
	if (eq(534775808, 440403968)) return 41;
	if (eq(1608515584, 448790528)) return 42;
	if (eq(1608515584, 1522532352)) return 43;
	if (eq(520093696, 452984832)) return 44;
	if (eq(4286586848, 503320576)) return 45;
	if (eq(4294966272, 505806848)) return 46;
	if (eq(4294966272, 2657484800)) return 47;
	if (eq(4294966272, 505872384)) return 48;
	if (eq(4294966272, 2657550336)) return 49;
	if (eq(4294966272, 509624320)) return 50;
	if (eq(4294966272, 505430016)) return 51;
	if (eq(4294966272, 509657088)) return 52;
	if (eq(4294966272, 505462784)) return 53;
	if (eq(4294966272, 509689856)) return 103;
	if (eq(4294966272, 505495552)) return 104;
	if (eq(4294966272, 509722624)) return 105;
	if (eq(4294966272, 505528320)) return 106;
	if (eq(4292934656, 2128663552)) return 54;
	if (eq(4292934656, 2116080640)) return 55;
	if (eq(4292934656, 509609984)) return 56;
	if (eq(4292934656, 505415680)) return 57;
	if (eq(4292934656, 509618176)) return 89;
	if (eq(4292934656, 505423872)) return 90;
	if (eq(4292934656, 509622272)) return 91;
	if (eq(4292934656, 505427968)) return 92;
	if (eq(4292934656, 509614080)) return 93;
	if (eq(4292934656, 505419776)) return 94;
	if (eq(4292902912, 524288e3)) return 95;
	if (eq(4292902912, 520093696)) return 96;
	if (eq(4292902912, 524320768)) return 97;
	if (eq(4292902912, 520126464)) return 98;
	if (eq(4292902912, 526385152)) return 99;
	if (eq(4292902912, 522190848)) return 100;
	if (eq(4292902912, 526417920)) return 101;
	if (eq(4292902912, 522223616)) return 102;
	if (eq(4292934687, 509616136)) return 60;
	if (eq(4292934687, 505421832)) return 61;
	if (eq(4292934687, 509616152)) return 60;
	if (eq(4292934687, 505421848)) return 61;
	if (eq(4292934687, 509616128)) return 58;
	if (eq(4292934687, 509616144)) return 58;
	if (eq(4292934687, 505421824)) return 59;
	if (eq(4292934687, 505421840)) return 59;
	if (eq(4292873216, 509611008)) return 62;
	if (eq(4292873216, 505416704)) return 63;
	if (eq(4292873216, 509608960)) return 64;
	if (eq(4292873216, 505414656)) return 65;
	if (eq(4294966272, 511180800)) return 66;
	if (eq(4294966272, 2658664448)) return 67;
	if (eq(4294966272, 511246336)) return 114;
	if (eq(4294966272, 2658729984)) return 115;
	if (eq(4294966272, 506003456)) return 116;
	if (eq(4294966272, 510197760)) return 117;
	if (eq(4294966272, 2653487104)) return 118;
	if (eq(4294966272, 2657681408)) return 119;
	if (eq(4294966272, 509739008)) return 68;
	if (eq(4294966272, 2657222656)) return 69;
	if (eq(4294966272, 509804544)) return 70;
	if (eq(4294966272, 2657288192)) return 71;
	if (eq(4294966272, 1583470592)) return 72;
	if (eq(4294966272, 2120341504)) return 73;
	if (eq(4294966272, 1579276288)) return 74;
	if (eq(4294966272, 2116147200)) return 75;
	if (eq(4294966272, 505544704)) return 108;
	if (eq(4294966272, 505610240)) return 109;
	if (eq(4294966272, 2653028352)) return 110;
	if (eq(4294966272, 2653093888)) return 111;
	if (eq(3206609920, 236985344)) return 76;
	if (eq(3206609920, 237011968)) return 112;
	if (eq(3206609920, 773882880)) return 113;
	if (eq(3219192832, 234896384)) return 77;
	if (eq(3219192832, 234884096)) return 78;
	if (eq(3219192832, 234882048)) return 79;
	if (eq(2683894784, 251716608)) return 80;
	if (eq(2683894784, 251659264)) return 80;
	if (eq(2683894784, 251667456)) return 80;
	if (eq(2683894784, 251675648)) return 80;
	if (eq(2683894784, 251683840)) return 80;
	if (eq(2683894784, 251692032)) return 80;
	if (eq(2683894784, 251700224)) return 80;
	if (eq(2683894784, 251708416)) return 80;
	if (eq(2683894784, 251712512)) return 80;
	if (eq(3219192832, 243283968)) return 81;
	if (eq(3219192832, 243275776)) return 82;
	if (eq(3219162112, 771751936)) return 83;
	if (eq(3206609920, 773866496)) return 84;
	if (eq(3212901376, 251700224)) return 85;
	if (eq(3219192832, 237000704)) return 120;
	if (eq(524286976, 238041088)) return 121;
	if (eq(4278254592, 1593857024)) return 88;
	if (eq(3204971520, 251941888)) return 107;
	return 0;
}
const PAGE_ALIGN = 4095;
var Cpu = class Cpu {
	/** x0..x30，index 31 = sp；按 lo/hi 两个 32 位字存（JIT 热路径用） */
	xlo = /* @__PURE__ */ new Int32Array(32);
	xhi = /* @__PURE__ */ new Int32Array(32);
	/** 向量寄存器 v0..v31：每寄存器 128 位 = 4 个 int32 / 2 个 double */
	vbuf = /* @__PURE__ */ new ArrayBuffer(512);
	vi = new Int32Array(this.vbuf);
	vf = new Float64Array(this.vbuf);
	/** 兼容视图：x[i] / v[i] 按 BigInt 读写（仅调试与解释器慢路径使用） */
	x = this.makeXView();
	v = this.makeVView();
	nzcv = 0;
	pc = 0;
	tick = 1048576;
	/** 已执行指令数（JIT 驱动用） */
	steps = 0;
	/** 独占监视器：LDXR/LDAXR 置位，STXR/STLXR 校验并清除 */
	monAddr = -1;
	monSize = 0;
	mem;
	svc;
	sysReg;
	/** 由宿主维护的系统寄存器 */
	tpidr = 0n;
	cntvct = () => 0n;
	/** 指令字 → 分类 的直接映射缓存（避免 Map 哈希） */
	clsWord = /* @__PURE__ */ new Int32Array(32768);
	clsKind = /* @__PURE__ */ new Uint8Array(32768);
	/** 指令分类直方图（性能分析用；histOn=false 时只有一次布尔判断） */
	histOn = false;
	hist = /* @__PURE__ */ new Int32Array(128);
	/** 调试：强制指定指令类走慢路径（SO_SLOW=all 或类 id 逗号列表） */
	slowCls = /* @__PURE__ */ new Uint8Array(128);
	/** 调试：SO_VERIFY=1 时逐条比对快慢路径 */
	verifyOn = process.env.SO_VERIFY === "1";
	/** 快路径已实现的指令类（调试对拍用） */
	static fastHas = (() => {
		const a = /* @__PURE__ */ new Uint8Array(128);
		for (const c of [
			14,
			37,
			29,
			15,
			35,
			13,
			31,
			30,
			12,
			11,
			21,
			33,
			17,
			36,
			76,
			77,
			20,
			39,
			28,
			46,
			78,
			79,
			18,
			19,
			23,
			22,
			32,
			34,
			16,
			40,
			41,
			24,
			25,
			1,
			4,
			5,
			6,
			7,
			8
		]) a[c] = 1;
		return a;
	})();
	fpBuf = /* @__PURE__ */ new ArrayBuffer(8);
	fpView = new DataView(this.fpBuf);
	constructor(mem) {
		this.mem = mem;
		const s = process.env.SO_SLOW;
		if (s) {
			if (s === "all") this.slowCls.fill(1);
			else for (const x of s.split(",")) this.slowCls[Number(x)] = 1;
		}
	}
	/**
	* x 的 BigInt 兼容视图：真实存储是 xlo/xhi 两个 32 位字，
	* 这里用 Proxy 提供 cpu.x[i] 的 BigInt 读写，供宿主代码与解释器慢路径使用。
	*/
	makeXView() {
		const xlo = this.xlo;
		const xhi = this.xhi;
		return new Proxy(/* @__PURE__ */ new BigUint64Array(32), {
			get(t, p) {
				if (typeof p === "string") {
					const i = +p;
					if (i >= 0 && i < 32 && (i | 0) === i) return BigInt(xhi[i] >>> 0) << 32n | BigInt(xlo[i] >>> 0);
				}
				return Reflect.get(t, p);
			},
			set(t, p, v) {
				if (typeof p === "string") {
					const i = +p;
					if (i >= 0 && i < 32 && (i | 0) === i) {
						const b = BigInt.asUintN(64, BigInt(v));
						xlo[i] = Number(b & 4294967295n);
						xhi[i] = Number(b >> 32n);
						return true;
					}
				}
				return Reflect.set(t, p, v);
			}
		});
	}
	/** v 的 BigInt 兼容视图：v[2i] = 低 64 位，v[2i+1] = 高 64 位 */
	makeVView() {
		const vi = this.vi;
		return new Proxy(/* @__PURE__ */ new BigUint64Array(64), {
			get(t, p) {
				if (typeof p === "string") {
					const j = +p;
					if (j >= 0 && j < 64 && (j | 0) === j) {
						const k = j * 2;
						return BigInt(vi[k + 1] >>> 0) << 32n | BigInt(vi[k] >>> 0);
					}
				}
				return Reflect.get(t, p);
			},
			set(t, p, v) {
				if (typeof p === "string") {
					const j = +p;
					if (j >= 0 && j < 64 && (j | 0) === j) {
						const b = BigInt.asUintN(64, BigInt(v));
						const k = j * 2;
						vi[k] = Number(b & 4294967295n);
						vi[k + 1] = Number(b >> 32n);
						return true;
					}
				}
				return Reflect.set(t, p, v);
			}
		});
	}
	/** 快照 / 恢复全部现场（嵌套调用 so 函数用，频率极低） */
	saveRegs() {
		const x = new Array(32);
		const v = new Array(64);
		for (let i = 0; i < 32; i++) x[i] = this.x[i];
		for (let i = 0; i < 64; i++) v[i] = this.v[i];
		return {
			x,
			v
		};
	}
	restoreRegs(s) {
		for (let i = 0; i < 32; i++) this.x[i] = s.x[i];
		for (let i = 0; i < 64; i++) this.v[i] = s.v[i];
	}
	/** 通用读：31 号读作 0 */
	rx(n) {
		return n === 31 ? 0n : this.x[n];
	}
	/** 通用写：31 号丢弃 */
	wx(n, val) {
		if (n !== 31) this.x[n] = val;
	}
	/** 含 sp：31 号就是 sp */
	rxn(n) {
		return this.x[n];
	}
	wxn(n, val) {
		this.x[n] = val;
	}
	/** 32 位视图 */
	rx32(n) {
		return this.rx(n) & MASK32;
	}
	/** 向量寄存器低 64 位 */
	vlo(i) {
		const k = i * 4;
		return BigInt(this.vi[k + 1] >>> 0) << 32n | BigInt(this.vi[k] >>> 0);
	}
	/** 向量寄存器高 64 位 */
	vhi(i) {
		const k = i * 4 + 2;
		return BigInt(this.vi[k + 1] >>> 0) << 32n | BigInt(this.vi[k] >>> 0);
	}
	setVlo(i, val) {
		const k = i * 4;
		this.vi[k] = Number(val & 4294967295n);
		this.vi[k + 1] = Number(val >> 32n & 4294967295n);
	}
	setVhi(i, val) {
		const k = i * 4 + 2;
		this.vi[k] = Number(val & 4294967295n);
		this.vi[k + 1] = Number(val >> 32n & 4294967295n);
	}
	/** 只算 N/Z，C/V 由调用方给 */
	nz(result, sf) {
		const r = result & (sf ? MASK64 : MASK32);
		return ((sf ? r >> 63n : r >> 31n) ? 8 : 0) | (r === 0n ? 4 : 0);
	}
	addsub(a, b, sub, sf, setF) {
		const M = sf ? MASK64 : MASK32;
		const signBit = sf ? 1n << 63n : 1n << 31n;
		const x = a & M;
		const y = b & M;
		if (sub) {
			const r = x - y & M;
			if (setF) {
				const c = x >= y ? 2 : 0;
				const v = ((x ^ y) & (x ^ r) & signBit) !== 0n ? 1 : 0;
				this.nzcv = this.nz(r, sf) | c | v;
			}
			return r;
		}
		const r = x + y & M;
		if (setF) {
			const c = r < x ? 2 : 0;
			const v = (~(x ^ y) & (x ^ r) & signBit) !== 0n ? 1 : 0;
			this.nzcv = this.nz(r, sf) | c | v;
		}
		return r;
	}
	cond(c) {
		if (c >= 14) return true;
		const nzcv = this.nzcv;
		const n = (nzcv & 8) !== 0;
		const z = (nzcv & 4) !== 0;
		const cy = (nzcv & 2) !== 0;
		const v = (nzcv & 1) !== 0;
		let r;
		switch (c >> 1) {
			case 0:
				r = z;
				break;
			case 1:
				r = cy;
				break;
			case 2:
				r = n;
				break;
			case 3:
				r = v;
				break;
			case 4:
				r = cy && !z;
				break;
			case 5:
				r = n === v;
				break;
			case 6:
				r = n === v && !z;
				break;
			default: r = true;
		}
		return (c & 1) !== 0 ? !r : r;
	}
	/** 移位寄存器操作数（LSL/LSR/ASR/ROR） */
	shiftReg(val, type, amount, sf) {
		const w = sf ? 64 : 32;
		const M = sf ? MASK64 : MASK32;
		const v = val & M;
		const a = BigInt(amount & w - 1);
		switch (type) {
			case 0: return v << a & M;
			case 1: return v >> a;
			case 2: return BigInt.asUintN(w, BigInt.asIntN(w, v) >> a);
			default: return a === 0n ? v : (v >> a | v << BigInt(w) - a) & M;
		}
	}
	/** 扩展寄存器操作数 */
	extendReg(val, opt, shift, sf) {
		const M = sf ? MASK64 : MASK32;
		let r;
		switch (opt) {
			case 0:
				r = val & 255n;
				break;
			case 1:
				r = val & 65535n;
				break;
			case 2:
				r = val & MASK32;
				break;
			case 3:
				r = val & MASK64;
				break;
			case 4:
				r = BigInt.asUintN(64, BigInt.asIntN(8, val));
				break;
			case 5:
				r = BigInt.asUintN(64, BigInt.asIntN(16, val));
				break;
			case 6:
				r = BigInt.asUintN(64, BigInt.asIntN(32, val));
				break;
			default: r = val & MASK64;
		}
		return r << BigInt(shift) & M;
	}
	ld(addr, size) {
		if ((addr & PAGE_ALIGN) !== (addr + size - 1 & PAGE_ALIGN) && size > 1) return this.mem.read(addr, size);
		return this.mem.read(addr, size);
	}
	st(addr, size, val) {
		this.mem.write(addr, size, val);
	}
	step() {
		const w = this.mem.fetch(this.pc);
		const wi = w | 0;
		const slot = (wi ^ wi >>> 15) & 32767;
		let c;
		if (this.clsWord[slot] === wi) c = this.clsKind[slot] - 1;
		else {
			c = classify(w);
			this.clsWord[slot] = wi;
			this.clsKind[slot] = c + 1;
		}
		if (this.histOn) this.hist[c] += 1;
		const next = this.pc + 4;
		this.pc = next;
		this.exec(c, w);
		this.steps += 1;
		if (this.tick-- <= 0) throw new Error(`指令预算耗尽 @0x${(this.pc - 4).toString(16)}`);
	}
	/**
	* 由 N:imms:immr 生成位掩码（逻辑立即数 / 位域用）。
	* 已验证：bitfield 的 425 条真实编码全部匹配。
	*/
	decodeBitMasks(N, imms, immr, sf) {
		const probe = N << 6 | ~imms & 63;
		const len = 31 - Math.clz32(probe);
		if (len < 1) throw new Error("非法位掩码");
		const esize = 1 << len;
		const levels = esize - 1;
		const S = imms & levels;
		const R = immr & levels;
		const emask = (1n << BigInt(esize)) - 1n;
		const welem = (1n << BigInt(S + 1)) - 1n;
		const elem = R === 0 ? welem : (welem >> BigInt(R) | welem << BigInt(esize - R)) & emask;
		const dsz = sf ? 64 : 32;
		let out = 0n;
		for (let i = 0; i < dsz; i += esize) out |= elem << BigInt(i);
		return out & (sf ? MASK64 : MASK32);
	}
	/** 访存实际访问字节数（含 128 位 Q 形式） */
	ldstBytes(w) {
		const size = w >>> 30;
		const V = w >>> 26 & 1;
		const opc = w >>> 22 & 3;
		return V === 1 && size === 0 && opc >= 2 ? 16 : 1 << size;
	}
	/** 单个寄存器的 load/store（size/opc/V 语义见 ARM ARM LDST 编码） */
	ldstOne(w, addr) {
		const size = w >>> 30;
		const bytes = this.ldstBytes(w);
		const V = w >>> 26 & 1;
		const opc = w >>> 22 & 3;
		const rt = w & 31;
		if (V === 1) {
			if (size === 0 && opc >= 2) {
				if (opc === 2) {
					this.st(addr, 8, this.vlo(rt));
					this.st(addr + 8, 8, this.vhi(rt));
				} else {
					this.setVlo(rt, this.ld(addr, 8));
					this.setVhi(rt, this.ld(addr + 8, 8));
				}
				return;
			}
			if (opc === 0) this.st(addr, bytes, this.vlo(rt));
			else if (opc === 1) {
				this.setVlo(rt, this.ld(addr, bytes));
				this.setVhi(rt, 0n);
			}
			return;
		}
		if (opc === 0) {
			this.st(addr, bytes, this.rx(rt));
			return;
		}
		if (opc === 1) {
			this.wx(rt, this.ld(addr, bytes));
			return;
		}
		if (size === 3) return;
		const sx = BigInt.asIntN(bytes * 8, this.ld(addr, bytes));
		this.wx(rt, size === 2 ? BigInt.asUintN(64, sx) : BigInt.asUintN(32, sx));
	}
	/** LDP/STP：idx 00=offset 01=post 10=offset 11=pre */
	ldstPair(w, rn, imm, idx) {
		const opc = w >>> 30;
		const L = w >>> 22 & 1;
		const V = w >>> 26 & 1;
		const bytes = V === 1 ? 4 << opc : opc === 2 ? 8 : 4;
		const rt = w & 31;
		const rt2 = w >>> 10 & 31;
		const base = Number(this.rxn(rn));
		const addr = idx === 1 ? base : base + Number(imm);
		if (L === 1) {
			if (V === 1) {
				if (bytes === 16) {
					this.setVlo(rt, this.ld(addr, 8));
					this.setVhi(rt, this.ld(addr + 8, 8));
					this.setVlo(rt2, this.ld(addr + 16, 8));
					this.setVhi(rt2, this.ld(addr + 24, 8));
				} else {
					this.setVlo(rt, this.ld(addr, bytes));
					this.setVhi(rt, 0n);
					this.setVlo(rt2, this.ld(addr + bytes, bytes));
					this.setVhi(rt2, 0n);
				}
			} else if (opc === 2) {
				this.wx(rt, this.ld(addr, 8));
				this.wx(rt2, this.ld(addr + 8, 8));
			} else if (opc === 1) {
				this.wx(rt, BigInt.asUintN(64, BigInt.asIntN(32, this.ld(addr, 4))));
				this.wx(rt2, BigInt.asUintN(64, BigInt.asIntN(32, this.ld(addr + 4, 4))));
			} else {
				this.wx(rt, this.ld(addr, 4));
				this.wx(rt2, this.ld(addr + 4, 4));
			}
		} else if (V === 1) {
			if (bytes === 16) {
				this.st(addr, 8, this.vlo(rt));
				this.st(addr + 8, 8, this.vhi(rt));
				this.st(addr + 16, 8, this.vlo(rt2));
				this.st(addr + 24, 8, this.vhi(rt2));
			} else {
				this.st(addr, bytes, this.vlo(rt));
				this.st(addr + bytes, bytes, this.vlo(rt2));
			}
		} else {
			this.st(addr, bytes, this.rx(rt));
			this.st(addr + bytes, bytes, this.rx(rt2));
		}
		if (idx === 1) this.wxn(rn, BigInt(base + Number(imm)));
		else if (idx === 3) this.wxn(rn, BigInt(base + Number(imm)));
	}
	getF64(i) {
		this.fpView.setBigUint64(0, this.vlo(i));
		return this.fpView.getFloat64(0);
	}
	setF64(i, v) {
		this.fpView.setFloat64(0, v);
		this.setVlo(i, this.fpView.getBigUint64(0));
		this.setVhi(i, 0n);
	}
	getF32(i) {
		this.fpView.setUint32(0, Number(this.vlo(i) & MASK32));
		return this.fpView.getFloat32(0);
	}
	setF32(i, v) {
		this.fpView.setFloat32(0, v);
		this.setVlo(i, BigInt(this.fpView.getUint32(0)));
		this.setVhi(i, 0n);
	}
	/** FCMP 风格的标志设置 */
	fpCompare(a, b) {
		if (Number.isNaN(a) || Number.isNaN(b)) this.nzcv = 3;
		else if (a < b) this.nzcv = 8;
		else if (a === b) this.nzcv = 6;
		else this.nzcv = 2;
	}
	/** VFPExpandImm：8 位立即数 → 浮点位模式（ARM ARM 定义） */
	vfpExpand(imm8, single) {
		const sign = imm8 >> 7 & 1;
		const b6 = imm8 >> 6 & 1;
		const low6 = imm8 & 63;
		const frac = BigInt(low6 & 15);
		if (single) {
			const exp = (b6 ^ 1) << 7 | (b6 ? 31 : 0) << 2 | low6 >> 4 & 3;
			return BigInt((sign << 31 | exp << 23) >>> 0) | frac << 19n;
		}
		const exp = (b6 ^ 1) << 10 | (b6 ? 255 : 0) << 2 | low6 >> 4 & 3;
		return BigInt(sign) << 63n | BigInt(exp) << 52n | frac << 48n;
	}
	/** 取向量寄存器第 index 个 esize 位元素（esize ∈ {8,16,32,64}） */
	getLane(reg, index, esize) {
		const bit = index * esize;
		const mask = (1n << BigInt(esize)) - 1n;
		return bit < 64 ? this.vlo(reg) >> BigInt(bit) & mask : this.vhi(reg) >> BigInt(bit - 64) & mask;
	}
	setLane(reg, index, esize, val) {
		const bit = index * esize;
		const mask = (1n << BigInt(esize)) - 1n;
		const x = val & mask;
		if (bit < 64) this.setVlo(reg, this.vlo(reg) & ~(mask << BigInt(bit)) | x << BigInt(bit));
		else {
			const s = bit - 64;
			this.setVhi(reg, this.vhi(reg) & ~(mask << BigInt(s)) | x << BigInt(s));
		}
	}
	/** 由 imm5 求元素位宽与 lane 下标 */
	imm5ToLane(imm5) {
		const low = imm5 & -imm5;
		const size = 31 - Math.clz32(low);
		return {
			esize: 8 << size,
			index: imm5 >> size + 1
		};
	}
	rlo = 0;
	rhi = 0;
	bmLo = 0;
	bmHi = 0;
	t1 = /* @__PURE__ */ new Int32Array(1);
	/** x[n] → rlo/rhi（n=31 读作 0） */
	gx(n) {
		if (n === 31) {
			this.rlo = 0;
			this.rhi = 0;
		} else {
			this.rlo = this.xlo[n];
			this.rhi = this.xhi[n];
		}
	}
	/** 含 sp 读 x[n] → rlo/rhi */
	gxs(n) {
		this.rlo = this.xlo[n];
		this.rhi = this.xhi[n];
	}
	/** rlo/rhi → x[rd]（rd=31 丢弃） */
	sx(rd) {
		if (rd !== 31) {
			this.xlo[rd] = this.rlo;
			this.xhi[rd] = this.rhi;
		}
	}
	/** rlo/rhi → x[rd]（含 sp） */
	sxs(rd) {
		this.xlo[rd] = this.rlo;
		this.xhi[rd] = this.rhi;
	}
	/** 写 32 位结果（零扩展到 64；rd=31 丢弃） */
	sx32(rd, v) {
		if (rd !== 31) {
			this.xlo[rd] = v;
			this.xhi[rd] = 0;
		}
	}
	/** 把 number（|v| < 2^53）写成 64 位寄存器值（rd=31 丢弃） */
	sxNum(rd, v) {
		if (rd === 31) return;
		this.xlo[rd] = v | 0;
		this.xhi[rd] = Math.floor(v / 4294967296) | 0;
	}
	/** 含 sp 版 */
	sxNumS(rd, v) {
		this.xlo[rd] = v | 0;
		this.xhi[rd] = Math.floor(v / 4294967296) | 0;
	}
	/** 读 64 位寄存器为 number（含 sp） */
	num(n) {
		return (this.xhi[n] >>> 0) * 4294967296 + (this.xlo[n] >>> 0);
	}
	/** rlo/rhi = a ± b；b 由参数给出，a 在 rlo/rhi。sf=0 时只保留低 32 位。 */
	addsubN(bLo, bHi, sub, sf, setF) {
		const aLo = this.rlo;
		const aHi = this.rhi;
		let lo;
		let hi;
		if (sf === 1) {
			if (sub) {
				const d = (aLo >>> 0) - (bLo >>> 0);
				const hd = (aHi >>> 0) - (bHi >>> 0) - (d < 0 ? 1 : 0);
				lo = d | 0;
				hi = hd | 0;
				if (setF) {
					const v = ((aHi ^ bHi) & (aHi ^ hi)) >>> 31 & 1;
					this.nzcv = hi >>> 31 << 3 | ((lo | hi) === 0 ? 1 : 0) << 2 | (hd < 0 ? 0 : 2) | (v ? 1 : 0);
				}
			} else {
				const s = (aLo >>> 0) + (bLo >>> 0);
				const hs = (aHi >>> 0) + (bHi >>> 0) + (s > 4294967295 ? 1 : 0);
				lo = s | 0;
				hi = hs | 0;
				if (setF) {
					const v = (~(aHi ^ bHi) & (aHi ^ hi)) >>> 31 & 1;
					this.nzcv = hi >>> 31 << 3 | ((lo | hi) === 0 ? 1 : 0) << 2 | (hs > 4294967295 ? 2 : 0) | (v ? 1 : 0);
				}
			}
		} else if (sub) {
			const d = (aLo >>> 0) - (bLo >>> 0);
			lo = d | 0;
			if (setF) {
				const v = ((aLo ^ bLo) & (aLo ^ lo)) >>> 31 & 1;
				this.nzcv = lo >>> 31 << 3 | (lo === 0 ? 1 : 0) << 2 | (d < 0 ? 0 : 2) | (v ? 1 : 0);
			}
			hi = 0;
		} else {
			const s = (aLo >>> 0) + (bLo >>> 0);
			lo = s | 0;
			if (setF) {
				const v = (~(aLo ^ bLo) & (aLo ^ lo)) >>> 31 & 1;
				this.nzcv = lo >>> 31 << 3 | (lo === 0 ? 1 : 0) << 2 | (s > 4294967295 ? 2 : 0) | (v ? 1 : 0);
			}
			hi = 0;
		}
		this.rlo = lo;
		this.rhi = hi;
	}
	/** rlo/rhi = rlo/rhi 逻辑/算术移位（type 0 LSL 1 LSR 2 ASR 3 ROR） */
	shiftN(type, amount, sf) {
		const alo = this.rlo;
		const ahi = this.rhi;
		if (sf === 1) {
			const n = amount & 63;
			if (type === 0) {
				if (n === 0) {
					this.rlo = alo;
					this.rhi = ahi;
				} else if (n < 32) {
					this.rlo = alo << n;
					this.rhi = ahi << n | alo >>> 32 - n;
				} else if (n === 32) {
					this.rlo = 0;
					this.rhi = alo;
				} else {
					this.rlo = 0;
					this.rhi = alo << n - 32;
				}
			} else if (type === 1) {
				if (n === 0) {
					this.rlo = alo;
					this.rhi = ahi;
				} else if (n < 32) {
					this.rlo = alo >>> n | ahi << 32 - n;
					this.rhi = ahi >>> n;
				} else if (n === 32) {
					this.rlo = ahi;
					this.rhi = 0;
				} else {
					this.rlo = ahi >>> n - 32;
					this.rhi = 0;
				}
			} else if (type === 2) {
				if (n === 0) {
					this.rlo = alo;
					this.rhi = ahi;
				} else if (n < 32) {
					this.rlo = alo >>> n | ahi << 32 - n;
					this.rhi = ahi >> n;
				} else if (n === 32) {
					this.rlo = ahi;
					this.rhi = ahi >> 31;
				} else {
					this.rlo = ahi >> n - 32;
					this.rhi = ahi >> 31;
				}
			} else if (n === 0) {
				this.rlo = alo;
				this.rhi = ahi;
			} else if (n < 32) {
				this.rlo = alo >>> n | ahi << 32 - n;
				this.rhi = ahi >>> n | alo << 32 - n;
			} else if (n === 32) {
				this.rlo = ahi;
				this.rhi = alo;
			} else {
				const m = n - 32;
				this.rlo = ahi >>> m | alo << 32 - m;
				this.rhi = alo >>> m | ahi << 32 - m;
			}
			return;
		}
		const n = amount & 31;
		if (type === 0) {
			this.rlo = alo << n;
			this.rhi = 0;
		} else if (type === 1) {
			this.rlo = alo >>> n;
			this.rhi = 0;
		} else if (type === 2) {
			this.rlo = alo >> n;
			this.rhi = 0;
		} else {
			this.rlo = n === 0 ? alo : alo >>> n | alo << 32 - n;
			this.rhi = 0;
		}
	}
	/** rlo/rhi = 扩展（option 0 UXTB … 7 SXTX）后左移 shift 位 */
	extendN(opt, shift, sf) {
		const alo = this.rlo;
		const ahi = this.rhi;
		let lo;
		let hi;
		switch (opt) {
			case 0:
				lo = alo & 255;
				hi = 0;
				break;
			case 1:
				lo = alo & 65535;
				hi = 0;
				break;
			case 2:
				lo = alo;
				hi = 0;
				break;
			case 3:
				lo = alo;
				hi = ahi;
				break;
			case 4:
				lo = alo << 24 >> 24;
				hi = lo >> 31;
				break;
			case 5:
				lo = alo << 16 >> 16;
				hi = lo >> 31;
				break;
			case 6:
				lo = alo;
				hi = alo >> 31;
				break;
			default:
				lo = alo;
				hi = ahi;
		}
		if (sf === 1) {
			const n = shift & 63;
			if (n === 0) {
				this.rlo = lo;
				this.rhi = hi;
			} else if (n < 32) {
				this.rlo = lo << n;
				this.rhi = hi << n | lo >>> 32 - n;
			} else {
				this.rlo = 0;
				this.rhi = lo << n - 32;
			}
		} else {
			this.rlo = lo << (shift & 31);
			this.rhi = 0;
		}
	}
	/** 从 64 位值里取 [offset, offset+width) 位到 rlo/rhi */
	extractN(slo, shi, offset, width) {
		if (offset === 0) {
			this.rlo = slo;
			this.rhi = shi;
		} else if (offset < 32) {
			this.rlo = slo >>> offset | shi << 32 - offset;
			this.rhi = shi >>> offset;
		} else if (offset === 32) {
			this.rlo = shi;
			this.rhi = 0;
		} else {
			this.rlo = shi >>> offset - 32;
			this.rhi = 0;
		}
		if (width < 32) {
			this.rlo &= (1 << width) - 1;
			this.rhi = 0;
		} else if (width === 32) this.rhi = 0;
		else if (width < 64) this.rhi &= (1 << width - 32) - 1;
	}
	/** 逻辑立即数掩码 → bmLo/bmHi（对应 decodeBitMasks 的 number 版） */
	decodeBitMasksNum(N, imms, immr, sf) {
		const probe = N << 6 | ~imms & 63;
		const len = 31 - Math.clz32(probe);
		if (len < 1) throw new Error("非法位掩码");
		const esize = 1 << len;
		const levels = esize - 1;
		const S = imms & levels;
		const R = immr & levels;
		if (esize === 64) {
			let wlo;
			let whi;
			if (S === 63) {
				wlo = -1;
				whi = -1;
			} else if (S < 31) {
				wlo = (1 << S + 1) - 1;
				whi = 0;
			} else if (S === 31) {
				wlo = -1;
				whi = 0;
			} else {
				wlo = -1;
				whi = (1 << S - 31) - 1;
			}
			if (R === 0) {
				this.bmLo = wlo;
				this.bmHi = whi;
			} else if (R < 32) {
				this.bmLo = wlo >>> R | whi << 32 - R;
				this.bmHi = whi >>> R | wlo << 32 - R;
			} else if (R === 32) {
				this.bmLo = whi;
				this.bmHi = wlo;
			} else {
				const m = R - 32;
				this.bmLo = whi >>> m | wlo << 32 - m;
				this.bmHi = wlo >>> m | whi << 32 - m;
			}
			return;
		}
		const emask = esize === 32 ? -1 : (1 << esize) - 1;
		const welem = S + 1 >= 32 ? -1 : (1 << S + 1) - 1;
		const elem = R === 0 ? welem : (welem >>> R | welem << esize - R) & emask;
		let rep;
		if (esize === 32) rep = elem;
		else if (esize === 16) rep = elem | elem << 16 | 0;
		else if (esize === 8) rep = elem * 16843009 | 0;
		else {
			rep = 0;
			for (let b = 0; b < 32; b += esize) rep |= elem << b;
		}
		this.bmLo = rep;
		this.bmHi = sf === 1 ? rep : 0;
	}
	/** 取向量通道（esize=64 时 lo/hi 都有值）→ rlo/rhi */
	laneN(reg, index, esize) {
		const vi = this.vi;
		const bit = index * esize;
		const k = reg * 4 + (bit >>> 5);
		if (esize === 64) {
			this.rlo = vi[k];
			this.rhi = vi[k + 1];
			return;
		}
		const sh = bit & 31;
		const v = vi[k] >>> sh | (sh === 0 ? 0 : vi[k + 1] << 32 - sh);
		this.rhi = 0;
		if (esize === 32) this.rlo = v | 0;
		else if (esize === 16) this.rlo = v & 65535;
		else this.rlo = v & 255;
	}
	/** 读一个 lane（esize=64 时只返回低 32 位，高 32 位需读 vi[k+1]） */
	laneOf(reg, i, esize) {
		const bit = i * esize;
		const k = reg * 4 + (bit >>> 5);
		const vi = this.vi;
		if (esize === 64) return vi[k];
		const sh = bit & 31;
		const v = vi[k] >>> sh | (sh === 0 ? 0 : vi[k + 1] << 32 - sh);
		return esize === 32 ? v | 0 : v & (1 << esize) - 1;
	}
	/** 写一个 lane（esize=64 时写 lo/hi） */
	setLaneOf(reg, i, esize, lo, hi = 0) {
		const bit = i * esize;
		const k = reg * 4 + (bit >>> 5);
		const vi = this.vi;
		if (esize === 64) {
			vi[k] = lo | 0;
			vi[k + 1] = hi | 0;
			return;
		}
		if (esize === 32) {
			vi[k] = lo | 0;
			return;
		}
		const sh = bit & 31;
		const full = esize === 16 ? 65535 : 255;
		const mask = full << sh;
		vi[k] = vi[k] & ~mask | lo << sh & mask;
		if (sh + esize > 32) {
			const sh2 = 32 - sh;
			const mask2 = full >>> sh2;
			vi[k + 1] = vi[k + 1] & ~mask2 | lo >>> sh2 & mask2;
		}
	}
	/** ZIP1 / UZP1 */
	vzipN(w, zip) {
		const Q = w >>> 30 & 1;
		const esize = 8 << (w >>> 22 & 3);
		const rm = w >>> 16 & 31;
		const rn = w >>> 5 & 31;
		const rd = w & 31;
		const lanes = (Q === 1 ? 128 : 64) / esize;
		const half = lanes >> 1;
		const as = [];
		const bs = [];
		const ah = [];
		const bh = [];
		for (let i = 0; i < lanes; i++) {
			as.push(this.laneOf(rn, i, esize));
			bs.push(this.laneOf(rm, i, esize));
			if (esize === 64) {
				ah.push(this.vi[rn * 4 + i * 2 + 1]);
				bh.push(this.vi[rm * 4 + i * 2 + 1]);
			}
		}
		for (let i = 0; i < half; i++) if (zip) {
			this.setLaneOf(rd, 2 * i, esize, as[i], ah[i] ?? 0);
			this.setLaneOf(rd, 2 * i + 1, esize, bs[i], bh[i] ?? 0);
		} else {
			this.setLaneOf(rd, i, esize, as[2 * i], ah[2 * i] ?? 0);
			this.setLaneOf(rd, half + i, esize, bs[2 * i], bh[2 * i] ?? 0);
		}
		if (Q === 0) {
			this.vi[rd * 4 + 2] = 0;
			this.vi[rd * 4 + 3] = 0;
		}
	}
	/** EXT：按字节把 rn||rm 右移 imm4 字节 */
	vextN(w) {
		const Q = w >>> 30 & 1;
		const imm4 = w >>> 11 & 15;
		const rm = w >>> 16 & 31;
		const rn = w >>> 5 & 31;
		const rd = w & 31;
		const vi = this.vi;
		const W = [
			vi[rn * 4],
			vi[rn * 4 + 1],
			vi[rn * 4 + 2],
			vi[rn * 4 + 3],
			vi[rm * 4],
			vi[rm * 4 + 1],
			vi[rm * 4 + 2],
			vi[rm * 4 + 3]
		];
		const sw = imm4 >>> 2;
		const sh = (imm4 & 3) * 8;
		const r0 = sh === 0 ? W[sw] : W[sw] >>> sh | W[sw + 1] << 32 - sh;
		const r1 = sh === 0 ? W[sw + 1] : W[sw + 1] >>> sh | W[sw + 2] << 32 - sh;
		const r2 = sh === 0 ? W[sw + 2] : W[sw + 2] >>> sh | W[sw + 3] << 32 - sh;
		const r3 = sh === 0 ? W[sw + 3] : W[sw + 3] >>> sh | W[sw + 4] << 32 - sh;
		vi[rd * 4] = r0;
		vi[rd * 4 + 1] = r1;
		vi[rd * 4 + 2] = Q === 1 ? r2 : 0;
		vi[rd * 4 + 3] = Q === 1 ? r3 : 0;
	}
	/** USHL（无符号右移形式） */
	vushlN(w) {
		const Q = w >>> 30 & 1;
		const esize = 8 << (w >>> 22 & 3);
		const rm = w >>> 16 & 31;
		const rn = w >>> 5 & 31;
		const rd = w & 31;
		const lanes = (Q === 1 ? 128 : 64) / esize;
		const mask = esize === 32 ? -1 : (1 << esize) - 1;
		const as = [];
		const bs = [];
		const ah = [];
		const bh = [];
		for (let i = 0; i < lanes; i++) {
			as.push(this.laneOf(rn, i, esize));
			bs.push(this.laneOf(rm, i, esize));
			if (esize === 64) {
				ah.push(this.vi[rn * 4 + i * 2 + 1]);
				bh.push(this.vi[rm * 4 + i * 2 + 1]);
			}
		}
		for (let i = 0; i < lanes; i++) {
			if (esize === 64) {
				const a = BigInt(ah[i] >>> 0) << 32n | BigInt(as[i] >>> 0);
				const sh = BigInt.asIntN(64, BigInt(bh[i] >>> 0) << 32n | BigInt(bs[i] >>> 0));
				let r;
				if (sh >= 64n || sh <= -64n) r = 0n;
				else if (sh >= 0n) r = a << sh & MASK64;
				else r = a >> -sh;
				this.setLaneOf(rd, i, 64, Number(r & 4294967295n) | 0, Number(r >> 32n) | 0);
				continue;
			}
			const sh = bs[i] << 32 - esize >> 32 - esize;
			let r;
			if (sh >= esize || sh <= -esize) r = 0;
			else if (sh >= 0) r = as[i] << sh & mask;
			else r = as[i] >>> -sh & mask;
			this.setLaneOf(rd, i, esize, r);
		}
		if (Q === 0) {
			this.vi[rd * 4 + 2] = 0;
			this.vi[rd * 4 + 3] = 0;
		}
	}
	/** DUP（element / general），镜像 execFast 的两条快路径 */
	vdupN(w, el) {
		const Q = w >>> 30 & 1;
		const lane = this.imm5ToLane(w >>> 16 & 31);
		const esize = lane.esize;
		if (el) this.laneN(w >>> 5 & 31, lane.index, esize);
		else this.gx(w >>> 5 & 31);
		let lo = this.rlo;
		let hi = this.rhi;
		if (esize !== 64) {
			const v = lo & (esize === 32 ? -1 : (1 << esize) - 1);
			if (esize === 32) {
				lo = v;
				hi = v;
			} else if (esize === 16) {
				lo = v | v << 16 | 0;
				hi = lo;
			} else {
				lo = v * 16843009 | 0;
				hi = lo;
			}
		}
		const k = (w & 31) * 4;
		const vi = this.vi;
		vi[k] = lo;
		vi[k + 1] = hi;
		vi[k + 2] = Q === 1 ? lo : 0;
		vi[k + 3] = Q === 1 ? hi : 0;
	}
	/** 单寄存器访存（number 版） */
	ldstOneN(w, addr) {
		const size = w >>> 30;
		const V = w >>> 26 & 1;
		const opc = w >>> 22 & 3;
		const rt = w & 31;
		const mem = this.mem;
		const vi = this.vi;
		if (V === 1) {
			const k = rt * 4;
			if (size === 0 && opc >= 2) {
				if (opc === 2) {
					mem.st64(addr, vi[k], vi[k + 1]);
					mem.st64(addr + 8, vi[k + 2], vi[k + 3]);
				} else {
					vi[k] = mem.ld64(addr, this.t1);
					vi[k + 1] = this.t1[0];
					vi[k + 2] = mem.ld64(addr + 8, this.t1);
					vi[k + 3] = this.t1[0];
				}
				return;
			}
			const bytes = 1 << size;
			if (opc === 0) {
				if (bytes === 8) mem.st64(addr, vi[k], vi[k + 1]);
				else if (bytes === 4) mem.st32(addr, vi[k]);
				else if (bytes === 2) mem.st16(addr, vi[k]);
				else mem.st8(addr, vi[k]);
				return;
			}
			if (opc !== 1) return;
			if (bytes === 8) {
				vi[k] = mem.ld64(addr, this.t1);
				vi[k + 1] = this.t1[0];
			} else {
				vi[k] = bytes === 4 ? mem.ld32(addr) : bytes === 2 ? mem.ld16(addr) : mem.ld8(addr);
				vi[k + 1] = 0;
			}
			vi[k + 2] = 0;
			vi[k + 3] = 0;
			return;
		}
		if (opc === 0) {
			const lo = rt === 31 ? 0 : this.xlo[rt];
			const hi = rt === 31 ? 0 : this.xhi[rt];
			if (size === 3) mem.st64(addr, lo, hi);
			else if (size === 2) mem.st32(addr, lo);
			else if (size === 1) mem.st16(addr, lo);
			else mem.st8(addr, lo);
			return;
		}
		if (opc === 1) {
			if (size === 3) {
				const lo = mem.ld64(addr, this.t1);
				if (rt !== 31) {
					this.xlo[rt] = lo;
					this.xhi[rt] = this.t1[0];
				}
			} else {
				const v = size === 2 ? mem.ld32(addr) : size === 1 ? mem.ld16(addr) : mem.ld8(addr);
				if (rt !== 31) {
					this.xlo[rt] = v;
					this.xhi[rt] = 0;
				}
			}
			return;
		}
		if (size === 3) return;
		const lo = size === 2 ? mem.ld32(addr) : size === 1 ? mem.ld16(addr) << 16 >> 16 : mem.ld8(addr) << 24 >> 24;
		if (rt === 31) return;
		this.xlo[rt] = lo;
		this.xhi[rt] = size === 2 ? lo >> 31 : 0;
	}
	/** 成对访存（number 版） */
	ldstPairN(w, base, imm, idx, rn) {
		const opc = w >>> 30;
		const L = w >>> 22 & 1;
		const V = w >>> 26 & 1;
		const bytes = V === 1 ? 4 << opc : opc === 2 ? 8 : 4;
		const rt = w & 31;
		const rt2 = w >>> 10 & 31;
		const addr = idx === 1 ? base : base + imm;
		const mem = this.mem;
		const vi = this.vi;
		if (L === 1) {
			if (V === 1) {
				if (bytes === 16) {
					let k = rt * 4;
					vi[k] = mem.ld64(addr, this.t1);
					vi[k + 1] = this.t1[0];
					vi[k + 2] = mem.ld64(addr + 8, this.t1);
					vi[k + 3] = this.t1[0];
					k = rt2 * 4;
					vi[k] = mem.ld64(addr + 16, this.t1);
					vi[k + 1] = this.t1[0];
					vi[k + 2] = mem.ld64(addr + 24, this.t1);
					vi[k + 3] = this.t1[0];
				} else {
					let k = rt * 4;
					if (bytes === 8) {
						vi[k] = mem.ld64(addr, this.t1);
						vi[k + 1] = this.t1[0];
					} else {
						vi[k] = mem.ld32(addr);
						vi[k + 1] = 0;
					}
					vi[k + 2] = 0;
					vi[k + 3] = 0;
					k = rt2 * 4;
					if (bytes === 8) {
						vi[k] = mem.ld64(addr + bytes, this.t1);
						vi[k + 1] = this.t1[0];
					} else {
						vi[k] = mem.ld32(addr + bytes);
						vi[k + 1] = 0;
					}
					vi[k + 2] = 0;
					vi[k + 3] = 0;
				}
			} else if (opc === 2) {
				if (rt !== 31) {
					this.xlo[rt] = mem.ld64(addr, this.t1);
					this.xhi[rt] = this.t1[0];
				}
				if (rt2 !== 31) {
					this.xlo[rt2] = mem.ld64(addr + 8, this.t1);
					this.xhi[rt2] = this.t1[0];
				}
			} else {
				const a = mem.ld32(addr);
				const b = mem.ld32(addr + 4);
				if (rt !== 31) {
					this.xlo[rt] = a;
					this.xhi[rt] = opc === 1 ? a >> 31 : 0;
				}
				if (rt2 !== 31) {
					this.xlo[rt2] = b;
					this.xhi[rt2] = opc === 1 ? b >> 31 : 0;
				}
			}
		} else if (V === 1) {
			if (bytes === 16) {
				const k = rt * 4;
				const k2 = rt2 * 4;
				mem.st64(addr, vi[k], vi[k + 1]);
				mem.st64(addr + 8, vi[k + 2], vi[k + 3]);
				mem.st64(addr + 16, vi[k2], vi[k2 + 1]);
				mem.st64(addr + 24, vi[k2 + 2], vi[k2 + 3]);
			} else if (bytes === 8) {
				mem.st64(addr, vi[rt * 4], vi[rt * 4 + 1]);
				mem.st64(addr + 8, vi[rt2 * 4], vi[rt2 * 4 + 1]);
			} else {
				mem.st32(addr, vi[rt * 4]);
				mem.st32(addr + 4, vi[rt2 * 4]);
			}
		} else if (bytes === 8) {
			mem.st64(addr, rt === 31 ? 0 : this.xlo[rt], rt === 31 ? 0 : this.xhi[rt]);
			mem.st64(addr + 8, rt2 === 31 ? 0 : this.xlo[rt2], rt2 === 31 ? 0 : this.xhi[rt2]);
		} else {
			mem.st32(addr, rt === 31 ? 0 : this.xlo[rt]);
			mem.st32(addr + 4, rt2 === 31 ? 0 : this.xlo[rt2]);
		}
		if (idx === 1 || idx === 3) this.sxNumS(rn, base + imm);
	}
	/**
	* 热路径解释器：覆盖 99.9% 的指令（按直方图），全部走 number 运算。
	* 其余指令类转发给 execSlow。
	*/
	exec(c, w) {
		if (this.slowCls[c] === 1) {
			this.execSlow(c, w);
			return;
		}
		if (this.verifyOn && Cpu.fastHas[c] === 1) {
			this.execVerify(c, w);
			return;
		}
		this.execFast(c, w);
	}
	/** 调试：快慢两条路径各跑一次，比较寄存器/标志/内存侧状态 */
	execVerify(c, w) {
		const slo = this.xlo.slice();
		const shi = this.xhi.slice();
		const svi = this.vi.slice();
		const snzcv = this.nzcv;
		const spc = this.pc;
		const smon = this.monAddr;
		this.mem.wlog = [];
		this.execFast(c, w);
		const fastLog = this.mem.wlog;
		this.mem.wlog = [];
		const flo = this.xlo.slice();
		const fhi = this.xhi.slice();
		const fvi = this.vi.slice();
		const fnzcv = this.nzcv;
		const fpc = this.pc;
		const fmon = this.monAddr;
		this.xlo.set(slo);
		this.xhi.set(shi);
		this.vi.set(svi);
		this.nzcv = snzcv;
		this.pc = spc;
		this.monAddr = smon;
		this.execSlow(c, w);
		const slowLog = this.mem.wlog;
		this.mem.wlog = null;
		const where = `pc=0x${(spc - 4).toString(16)} cls=${c} w=0x${(w >>> 0).toString(16)}`;
		if (fastLog.length !== slowLog.length) {
			console.error(`VERIFY ${where} 写内存次数 fast=${JSON.stringify(fastLog)} slow=${JSON.stringify(slowLog)}`);
			throw new Error(`${where} 写内存次数 fast=${fastLog.length / 4} slow=${slowLog.length / 4}`);
		}
		for (let i = 0; i < slowLog.length; i++) if (fastLog[i] !== slowLog[i]) {
			console.error(`VERIFY ${where} 写内存差异 @${i} fast=${JSON.stringify(fastLog)} slow=${JSON.stringify(slowLog)} x2snap=${shi[2] >>> 0}:${slo[2] >>> 0} x2slow=${this.xhi[2] >>> 0}:${this.xlo[2] >>> 0}`);
			throw new Error(`${where} 写内存差异 @${i}`);
		}
		for (let i = 0; i < 32; i++) if (flo[i] !== this.xlo[i] || fhi[i] !== this.xhi[i]) throw new Error(`${where} x${i} fast=${fhi[i] >>> 0}:${flo[i] >>> 0} slow=${this.xhi[i] >>> 0}:${this.xlo[i] >>> 0}`);
		for (let i = 0; i < 64; i++) if (fvi[i] !== this.vi[i]) throw new Error(`${where} v[${i >> 2}].w${i & 3} fast=${fvi[i] >>> 0} slow=${this.vi[i] >>> 0}`);
		if (fnzcv !== this.nzcv) throw new Error(`${where} nzcv fast=${fnzcv} slow=${this.nzcv}`);
		if (fpc !== this.pc) throw new Error(`${where} pc fast=0x${fpc.toString(16)} slow=0x${this.pc.toString(16)}`);
		if (fmon !== this.monAddr) throw new Error(`${where} monAddr fast=0x${fmon.toString(16)} slow=0x${this.monAddr.toString(16)}`);
	}
	/** 快路径（number 版）主体 */
	execFast(c, w) {
		switch (c) {
			case 14: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const hw = w >>> 21 & 3;
				const imm16 = w >>> 5 & 65535;
				const rd = w & 31;
				const shift = hw * 16;
				if (opc === 2) {
					if (shift < 32) this.sx32(rd, imm16 << shift);
					else if (rd !== 31) {
						this.xlo[rd] = 0;
						this.xhi[rd] = imm16 << shift - 32;
					}
					return;
				}
				if (opc === 0) {
					let vlo = 0;
					let vhi = 0;
					if (shift < 32) {
						vlo = imm16 << shift;
						vhi = shift === 0 ? 0 : imm16 >>> 32 - shift;
					} else vhi = imm16 << shift - 32;
					this.rlo = ~vlo;
					this.rhi = sf === 1 ? ~vhi : 0;
					this.sx(rd);
					return;
				}
				if (opc === 3) {
					const cl = rd === 31 ? 0 : this.xlo[rd];
					const ch = rd === 31 || sf === 0 ? 0 : this.xhi[rd];
					if (shift < 32) {
						this.rlo = cl & ~(65535 << shift) | imm16 << shift;
						this.rhi = ch;
					} else {
						this.rlo = cl;
						this.rhi = ch & ~(65535 << shift - 32) | imm16 << shift - 32;
					}
					this.sx(rd);
					return;
				}
				this.execSlow(c, w);
				return;
			}
			case 37: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const shift = w >>> 22 & 3;
				const N = w >>> 21 & 1;
				const imm6 = w >>> 10 & 63;
				const rm = w >>> 16 & 31;
				this.gx(rm);
				this.shiftN(shift, imm6, sf);
				if (N === 1) {
					this.rlo = ~this.rlo;
					if (sf === 1) this.rhi = ~this.rhi;
				}
				const bLo = this.rlo;
				const bHi = this.rhi;
				this.gx(w >>> 5 & 31);
				const aLo = this.rlo;
				const aHi = this.rhi;
				let lo;
				let hi;
				if (opc === 0) {
					lo = aLo & bLo;
					hi = aHi & bHi;
				} else if (opc === 1) {
					lo = aLo | bLo;
					hi = aHi | bHi;
				} else if (opc === 2) {
					lo = aLo ^ bLo;
					hi = aHi ^ bHi;
				} else {
					lo = aLo & bLo;
					hi = aHi & bHi;
				}
				const rd = w & 31;
				if (sf === 0) hi = 0;
				if (opc === 3) {
					this.nzcv = hi >>> 31 << 3 | ((lo | hi) === 0 ? 1 : 0) << 2;
					this.sx32(rd, lo);
				} else {
					this.rlo = lo;
					this.rhi = hi;
					this.sx(rd);
				}
				return;
			}
			case 29: {
				const rn = w >>> 5 & 31;
				this.ldstOneN(w, this.num(rn) + (w >>> 10 & 4095) * this.ldstBytes(w));
				return;
			}
			case 15: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const immr = w >>> 16 & 63;
				const imms = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const dsz = sf === 1 ? 64 : 32;
				const slo = rn === 31 ? 0 : this.xlo[rn];
				const shi = sf === 1 && rn !== 31 ? this.xhi[rn] : 0;
				let width;
				let lsb;
				if (imms >= immr) {
					width = imms - immr + 1;
					lsb = 0;
					this.extractN(slo, shi, immr, width);
				} else {
					width = imms + 1;
					lsb = dsz - immr;
					this.extractN(slo, shi, 0, width);
				}
				if (opc === 0 && width < dsz) {
					if ((width <= 32 ? this.rlo >>> width - 1 & 1 : this.rhi >>> width - 33 & 1) === 1) {
						if (width < 32) {
							this.rlo |= ~((1 << width) - 1);
							this.rhi = -1;
						} else if (width === 32) this.rhi = -1;
						else this.rhi |= ~((1 << width - 32) - 1);
					}
				}
				if (opc === 0 || opc === 2) {
					this.shiftN(0, lsb, sf);
					this.sx(rd);
					return;
				}
				this.shiftN(0, lsb, sf);
				const xLo = this.rlo;
				const xHi = this.rhi;
				let mLo = 0;
				let mHi = 0;
				if (lsb < 32) {
					const loBits = Math.min(width, 32 - lsb);
					mLo = loBits >= 32 ? -1 : (1 << loBits) - 1 << lsb;
					if (width > loBits) {
						const hiBits = width - loBits;
						mHi = hiBits >= 32 ? -1 : (1 << hiBits) - 1;
					}
				} else {
					const hiBits = Math.min(width, 64 - lsb);
					mHi = hiBits >= 32 ? -1 : (1 << hiBits) - 1 << lsb - 32;
				}
				if (rd !== 31) {
					this.xlo[rd] = xLo | this.xlo[rd] & ~mLo;
					this.xhi[rd] = sf === 1 ? xHi | this.xhi[rd] & ~mHi : 0;
				}
				return;
			}
			case 35: {
				const sf = w >>> 31;
				const sub = (w >>> 30 & 1) === 1;
				const setF = (w >>> 29 & 1) === 1;
				const shift = w >>> 22 & 3;
				const rm = w >>> 16 & 31;
				this.gx(rm);
				this.shiftN(shift, w >>> 10 & 63, sf);
				const bLo = this.rlo;
				const bHi = this.rhi;
				this.gx(w >>> 5 & 31);
				this.addsubN(bLo, bHi, sub, sf, setF);
				if (setF) {
					if (sf === 1) this.sx(w & 31);
					else this.sx32(w & 31, this.rlo);
				} else this.sx(w & 31);
				return;
			}
			case 13: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				this.decodeBitMasksNum(w >>> 22 & 1, w >>> 10 & 63, w >>> 16 & 63, sf);
				const rn = w >>> 5 & 31;
				this.gx(rn);
				const aLo = this.rlo;
				const aHi = this.rhi;
				let lo;
				let hi;
				if (opc === 0) {
					lo = aLo & this.bmLo;
					hi = aHi & this.bmHi;
				} else if (opc === 1) {
					lo = aLo | this.bmLo;
					hi = aHi | this.bmHi;
				} else if (opc === 2) {
					lo = aLo ^ this.bmLo;
					hi = aHi ^ this.bmHi;
				} else {
					lo = aLo & this.bmLo;
					hi = aHi & this.bmHi;
				}
				if (sf === 0) hi = 0;
				const rd = w & 31;
				if (opc === 3) {
					this.nzcv = hi >>> 31 << 3 | ((lo | hi) === 0 ? 1 : 0) << 2;
					this.sx32(rd, lo);
				} else {
					this.rlo = lo;
					this.rhi = hi;
					this.sx(rd);
				}
				return;
			}
			case 31: {
				const rn = w >>> 5 & 31;
				const off = (w >>> 12 & 511) << 23 >> 23;
				this.ldstOneN(w, this.num(rn) + off);
				return;
			}
			case 30: {
				const rn = w >>> 5 & 31;
				const size = w >>> 30;
				const S = w >>> 12 & 1;
				const bytes = this.ldstBytes(w);
				const shift = S === 1 ? bytes === 16 ? 4 : size : 0;
				this.gx(w >>> 16 & 31);
				this.extendN(w >>> 13 & 7, shift, 1);
				const addr = this.num(rn) + this.rhi * 4294967296 + (this.rlo >>> 0);
				this.ldstOneN(w, addr);
				return;
			}
			case 12: {
				const sf = w >>> 31;
				const sub = (w >>> 30 & 1) === 1;
				const setF = (w >>> 29 & 1) === 1;
				const sh = w >>> 22 & 1;
				const imm = (w >>> 10 & 4095) << (sh === 1 ? 12 : 0);
				this.gxs(w >>> 5 & 31);
				this.addsubN(imm, 0, sub, sf, setF);
				if (setF) {
					if (sf === 1) this.sx(w & 31);
					else this.sx32(w & 31, this.rlo);
				} else this.sxs(w & 31);
				return;
			}
			case 11: {
				const off = ((w >> 5 & 524287) << 2 | w >>> 29 & 3) << 11 >> 11;
				const pc0 = this.pc - 4;
				this.sxNum(w & 31, w >>> 31 === 1 ? (pc0 & -4096) + off * 4096 : pc0 + off);
				return;
			}
			case 21:
				this.pc = this.num(w >>> 5 & 31);
				return;
			case 33: {
				const rn = w >>> 5 & 31;
				const off = (w >>> 12 & 511) << 23 >> 23;
				const base = this.num(rn) + off;
				this.sxNumS(rn, base);
				this.ldstOneN(w, base);
				return;
			}
			case 17:
				if (this.cond(w & 15)) {
					const off = (w >>> 5 & 524287) << 13 >> 13;
					this.pc = this.pc - 4 + off * 4;
				}
				return;
			case 36: {
				const sf = w >>> 31;
				const sub = (w >>> 30 & 1) === 1;
				const setF = (w >>> 29 & 1) === 1;
				this.gx(w >>> 16 & 31);
				this.extendN(w >>> 13 & 7, w >>> 10 & 7, sf);
				const bLo = this.rlo;
				const bHi = this.rhi;
				this.gxs(w >>> 5 & 31);
				this.addsubN(bLo, bHi, sub, sf, setF);
				if (setF) {
					if (sf === 1) this.sx(w & 31);
					else this.sx32(w & 31, this.rlo);
				} else this.sxs(w & 31);
				return;
			}
			case 76: {
				const Q = w >>> 30 & 1;
				const op = (w >>> 29 & 1) << 2 | w >>> 22 & 3;
				const k = (w & 31) * 4;
				const an = (w >>> 5 & 31) * 4;
				const am = (w >>> 16 & 31) * 4;
				const vi = this.vi;
				const a0 = vi[an];
				const a1 = vi[an + 1];
				const a2 = vi[an + 2];
				const a3 = vi[an + 3];
				const b0 = vi[am];
				const b1 = vi[am + 1];
				const b2 = vi[am + 2];
				const b3 = vi[am + 3];
				let lo0;
				let lo1;
				let hi0;
				let hi1;
				if (op === 0) {
					lo0 = a0 & b0;
					lo1 = a1 & b1;
					hi0 = a2 & b2;
					hi1 = a3 & b3;
				} else if (op === 1) {
					lo0 = a0 & ~b0;
					lo1 = a1 & ~b1;
					hi0 = a2 & ~b2;
					hi1 = a3 & ~b3;
				} else if (op === 2) {
					lo0 = a0 | b0;
					lo1 = a1 | b1;
					hi0 = a2 | b2;
					hi1 = a3 | b3;
				} else if (op === 3) {
					lo0 = a0 | ~b0;
					lo1 = a1 | ~b1;
					hi0 = a2 | ~b2;
					hi1 = a3 | ~b3;
				} else if (op === 4) {
					lo0 = a0 ^ b0;
					lo1 = a1 ^ b1;
					hi0 = a2 ^ b2;
					hi1 = a3 ^ b3;
				} else {
					const d0 = vi[k];
					const d1 = vi[k + 1];
					const d2 = vi[k + 2];
					const d3 = vi[k + 3];
					if (op === 5 || op === 6) {
						lo0 = a0 & b0 | ~a0 & d0;
						lo1 = a1 & b1 | ~a1 & d1;
						hi0 = a2 & b2 | ~a2 & d2;
						hi1 = a3 & b3 | ~a3 & d3;
					} else {
						lo0 = a0 & d0 | ~a0 & b0;
						lo1 = a1 & d1 | ~a1 & b1;
						hi0 = a2 & d2 | ~a2 & b2;
						hi1 = a3 & d3 | ~a3 & b3;
					}
				}
				vi[k] = lo0;
				vi[k + 1] = lo1;
				if (Q === 1) {
					vi[k + 2] = hi0;
					vi[k + 3] = hi1;
				} else {
					vi[k + 2] = 0;
					vi[k + 3] = 0;
				}
				return;
			}
			case 77: {
				const Q = w >>> 30 & 1;
				const lane = this.imm5ToLane(w >>> 16 & 31);
				this.laneN(w >>> 5 & 31, lane.index, lane.esize);
				const rd = w & 31;
				if (rd !== 31) {
					this.xlo[rd] = this.rlo;
					this.xhi[rd] = lane.esize === 64 && Q === 1 ? this.rhi : 0;
				}
				return;
			}
			case 20: {
				const off = (w & 67108863) << 6 >> 6;
				if (w >>> 31 === 1) this.sxNum(30, this.pc);
				this.pc = this.pc - 4 + off * 4;
				return;
			}
			case 39: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const rm = w >>> 16 & 31;
				const op2 = w >>> 10 & 3;
				const rd = w & 31;
				if (this.cond(w >>> 12 & 15)) this.gx(w >>> 5 & 31);
				else {
					this.gx(rm);
					if (op === 0) {
						if (op2 === 1) {
							if (sf === 1) {
								const s = (this.rlo >>> 0) + 1;
								this.rlo = s | 0;
								if (s > 4294967295) this.rhi = this.rhi + 1 | 0;
							} else this.rlo = this.rlo + 1 | 0;
						}
					} else if (op2 === 0) {
						this.rlo = ~this.rlo;
						if (sf === 1) this.rhi = ~this.rhi;
					} else if (sf === 1) {
						const s = this.rlo >>> 0 === 0 ? 1 : 0;
						this.rlo = ~this.rlo + 1 | 0;
						this.rhi = ~this.rhi + s | 0;
					} else this.rlo = ~this.rlo + 1 | 0;
				}
				if (sf === 0) this.rhi = 0;
				this.sxs(rd);
				return;
			}
			case 28: {
				const rn = w >>> 5 & 31;
				const raw = w >>> 15 & 127;
				const opc = w >>> 30;
				const scale = (w >>> 26 & 1) === 1 ? 4 << opc : opc === 2 ? 8 : 4;
				this.ldstPairN(w, this.num(rn), (raw << 25 >> 25) * scale, w >>> 23 & 3, rn);
				return;
			}
			case 46: {
				const k = (w >>> 5 & 31) * 4;
				this.sx32(w & 31, this.vi[k]);
				return;
			}
			case 78: {
				const Q = w >>> 30 & 1;
				const esize = this.imm5ToLane(w >>> 16 & 31).esize;
				this.gx(w >>> 5 & 31);
				let lo;
				let hi;
				if (esize === 64) {
					lo = this.rlo;
					hi = this.rhi;
				} else {
					const v = this.rlo & (esize === 32 ? -1 : (1 << esize) - 1);
					if (esize === 32) {
						lo = v;
						hi = v;
					} else if (esize === 16) {
						lo = v | v << 16 | 0;
						hi = lo;
					} else {
						lo = v * 16843009 | 0;
						hi = lo;
					}
				}
				const k = (w & 31) * 4;
				const vi = this.vi;
				vi[k] = lo;
				vi[k + 1] = hi;
				vi[k + 2] = Q === 1 ? lo : 0;
				vi[k + 3] = Q === 1 ? hi : 0;
				return;
			}
			case 79: {
				const Q = w >>> 30 & 1;
				const lane = this.imm5ToLane(w >>> 16 & 31);
				const esize = lane.esize;
				this.laneN(w >>> 5 & 31, lane.index, esize);
				let lo;
				let hi;
				if (esize === 64) {
					lo = this.rlo;
					hi = this.rhi;
				} else {
					const v = this.rlo;
					if (esize === 32) {
						lo = v;
						hi = v;
					} else if (esize === 16) {
						lo = v | v << 16 | 0;
						hi = lo;
					} else {
						lo = v * 16843009 | 0;
						hi = lo;
					}
				}
				const k = (w & 31) * 4;
				const vi = this.vi;
				vi[k] = lo;
				vi[k + 1] = hi;
				vi[k + 2] = Q === 1 ? lo : 0;
				vi[k + 3] = Q === 1 ? hi : 0;
				return;
			}
			case 18: {
				const rt = w & 31;
				const sf = w >>> 31;
				const v = rt === 31 ? 0 : sf === 1 ? this.xlo[rt] | this.xhi[rt] : this.xlo[rt];
				const nz = w >>> 24 & 1;
				if (v === 0 !== (nz === 1)) {
					const off = (w >>> 5 & 524287) << 13 >> 13;
					this.pc = this.pc - 4 + off * 4;
				}
				return;
			}
			case 19: {
				const bit = (w >>> 31 & 1) << 5 | w >>> 19 & 31;
				const rt = w & 31;
				if ((rt === 31 ? 0 : bit < 32 ? this.xlo[rt] >>> bit & 1 : this.xhi[rt] >>> bit - 32 & 1) === (w >>> 24 & 1)) {
					const off = (w >>> 5 & 16383) << 18 >> 18;
					this.pc = this.pc - 4 + off * 4;
				}
				return;
			}
			case 23:
			case 22: {
				const t = this.num(w >>> 5 & 31);
				if (c === 22) this.sxNum(30, this.pc);
				this.pc = t;
				return;
			}
			case 32: {
				const rn = w >>> 5 & 31;
				const off = (w >>> 12 & 511) << 23 >> 23;
				const base = this.num(rn);
				this.ldstOneN(w, base);
				this.sxNumS(rn, base + off);
				return;
			}
			case 34: {
				const off = (w >>> 5 & 524287) << 13 >> 13;
				this.ldstOneN(w, this.pc - 4 + off * 4);
				return;
			}
			case 16: {
				const sf = w >>> 31;
				const rm = w >>> 16 & 31;
				const lsb = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				this.gx(rm);
				const bLo = this.rlo;
				const bHi = this.rhi;
				this.gx(rn);
				const aLo = this.rlo;
				const aHi = this.rhi;
				const rd = w & 31;
				if (sf === 0) {
					const n = lsb & 31;
					this.rlo = n === 0 ? bLo : bLo >>> n | aLo << 32 - n;
					this.rhi = 0;
				} else if (lsb === 0) {
					this.rlo = bLo;
					this.rhi = bHi;
				} else if (lsb < 32) {
					this.rlo = bLo >>> lsb | bHi << 32 - lsb;
					this.rhi = bHi >>> lsb | aLo << 32 - lsb;
				} else if (lsb === 32) {
					this.rlo = bHi;
					this.rhi = aLo;
				} else {
					const m = lsb - 32;
					this.rlo = bHi >>> m | aLo << 32 - m;
					this.rhi = aLo >>> m | aHi << 32 - m;
				}
				this.sx(rd);
				return;
			}
			case 40:
			case 41: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				if (!this.cond(w >>> 12 & 15)) {
					this.nzcv = w & 15;
					return;
				}
				if (c === 41) {
					this.gx(w >>> 5 & 31);
					this.addsubN(w >>> 16 & 31, 0, op === 1, sf, true);
				} else {
					this.gx(w >>> 16 & 31);
					const bLo = this.rlo;
					const bHi = this.rhi;
					this.gx(w >>> 5 & 31);
					this.addsubN(bLo, bHi, op === 1, sf, true);
				}
				return;
			}
			case 24:
			case 25: {
				const rn = w >>> 5 & 31;
				const addr = rn === 31 ? 0 : this.num(rn);
				const rt = w & 31;
				const size = w >>> 30;
				if (c === 24) {
					if (rt !== 31) {
						if (size === 3) {
							this.xlo[rt] = this.mem.ld64(addr, this.t1);
							this.xhi[rt] = this.t1[0];
						} else {
							this.xlo[rt] = size === 2 ? this.mem.ld32(addr) : size === 1 ? this.mem.ld16(addr) : this.mem.ld8(addr);
							this.xhi[rt] = 0;
						}
					}
				} else if (size === 3) this.mem.st64(addr, this.xlo[rt], this.xhi[rt]);
				else if (size === 2) this.mem.st32(addr, this.xlo[rt]);
				else if (size === 1) this.mem.st16(addr, this.xlo[rt]);
				else this.mem.st8(addr, this.xlo[rt]);
				return;
			}
			case 1:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8: return;
			default: this.execSlow(c, w);
		}
	}
	/** 慢路径：冷门指令类（保留 BigInt 实现，经 cpu.x Proxy 读写） */
	execSlow(c, w) {
		switch (c) {
			case 11: {
				const imm = (w >> 5 & 524287) << 2 | w >>> 29 & 3;
				const off = BigInt.asIntN(21, BigInt(imm));
				const pc = BigInt(this.pc - 4);
				const v = w >>> 31 === 1 ? (pc & -4096n) + (off << 12n) : pc + off;
				this.wx(w & 31, v & MASK64);
				return;
			}
			case 12: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const S = w >>> 29 & 1;
				const sh = w >>> 22 & 1;
				const imm12 = w >>> 10 & 4095;
				const imm = BigInt(sh ? imm12 << 12 : imm12);
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const r = this.addsub(this.rxn(rn), imm, op === 1, sf, S === 1);
				if (S === 1) this.wx(rd, r);
				else this.wxn(rd, r);
				return;
			}
			case 13: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const N = w >>> 22 & 1;
				const immr = w >>> 16 & 63;
				const imms = w >>> 10 & 63;
				const imm = this.decodeBitMasks(N, imms, immr, sf);
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const M = sf ? MASK64 : MASK32;
				const a = this.rx(rn) & M;
				let r;
				if (opc === 0) r = a & imm;
				else if (opc === 1) r = a | imm;
				else if (opc === 2) r = a ^ imm;
				else {
					r = a & imm;
					this.nzcv = this.nz(r, sf);
				}
				r &= M;
				if (opc === 3) this.wx(rd, r);
				else this.wxn(rd, r);
				return;
			}
			case 14: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const hw = w >>> 21 & 3;
				const imm16 = BigInt(w >>> 5 & 65535);
				const shift = BigInt(hw * 16);
				const rd = w & 31;
				const M = sf ? MASK64 : MASK32;
				let r;
				if (opc === 0) r = ~(imm16 << shift) & M;
				else if (opc === 2) r = imm16 << shift & M;
				else {
					const mask = 65535n << shift;
					r = this.rx(rd) & ~mask & M | imm16 << shift & M;
				}
				this.wx(rd, r);
				return;
			}
			case 15: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const immr = w >>> 16 & 63;
				const imms = w >>> 10 & 63;
				const dsz = sf ? 64 : 32;
				const M = sf ? MASK64 : MASK32;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const src = this.rx(rn) & M;
				let width;
				let lsb;
				let val;
				if (imms >= immr) {
					width = imms - immr + 1;
					val = src >> BigInt(immr) & (1n << BigInt(width)) - 1n;
					lsb = 0;
				} else {
					width = imms + 1;
					val = src & (1n << BigInt(width)) - 1n;
					lsb = dsz - immr;
				}
				if (opc === 0) {
					if (val >> BigInt(width - 1) & 1n) val |= M ^ (1n << BigInt(width)) - 1n;
					this.wx(rd, val << BigInt(lsb) & M);
				} else if (opc === 2) this.wx(rd, val << BigInt(lsb) & M);
				else {
					const fieldMask = (1n << BigInt(width)) - 1n << BigInt(lsb) & M;
					const r = val << BigInt(lsb) & M | this.rx(rd) & (M ^ fieldMask);
					this.wx(rd, r);
				}
				return;
			}
			case 16: {
				const sf = w >>> 31;
				const Rm = w >>> 16 & 31;
				const lsb = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const bits = sf ? 64 : 32;
				const M = sf ? MASK64 : MASK32;
				const a = this.rx(rn) & M;
				const b = this.rx(Rm) & M;
				let r;
				if (lsb === 0) r = b;
				else r = (b >> BigInt(lsb) | a << BigInt(bits - lsb)) & M;
				this.wx(rd, r);
				return;
			}
			case 20: {
				const off = BigInt.asIntN(26, BigInt(w & 67108863)) << 2n;
				const target = Number(BigInt(this.pc - 4) + off);
				if (w >>> 31) this.x[30] = BigInt(this.pc);
				this.pc = target;
				return;
			}
			case 17: {
				const cond = w & 15;
				const off = BigInt.asIntN(19, BigInt(w >>> 5 & 524287)) << 2n;
				if (this.cond(cond)) this.pc = Number(BigInt(this.pc - 4) + off);
				return;
			}
			case 18: {
				const sf = w >>> 31;
				const nz = w >>> 24 & 1;
				const off = BigInt.asIntN(19, BigInt(w >>> 5 & 524287)) << 2n;
				if ((this.rx(w & 31) & (sf ? MASK64 : MASK32)) === 0n !== (nz === 1)) this.pc = Number(BigInt(this.pc - 4) + off);
				return;
			}
			case 19: {
				const nz = w >>> 24 & 1;
				const bit = (w >>> 31 & 1) << 5 | w >>> 19 & 31;
				const off = BigInt.asIntN(14, BigInt(w >>> 5 & 16383)) << 2n;
				if ((this.rx(w & 31) >> BigInt(bit) & 1n) === 1n === (nz === 1)) this.pc = Number(BigInt(this.pc - 4) + off);
				return;
			}
			case 21:
				this.pc = Number(this.rx(w >>> 5 & 31));
				return;
			case 22: {
				const t = Number(this.rx(w >>> 5 & 31));
				this.x[30] = BigInt(this.pc);
				this.pc = t;
				return;
			}
			case 23:
				this.pc = Number(this.rx(w >>> 5 & 31));
				return;
			case 2:
				if (this.svc) this.svc(this, w >>> 5 & 65535);
				else throw new Error(`未提供 svc 处理器 @0x${(this.pc - 4).toString(16)}`);
				return;
			case 3: throw new Error(`brk #${w >>> 5 & 65535} @0x${(this.pc - 4).toString(16)}`);
			case 9:
			case 10: {
				const isRead = c === 9;
				const key = w >>> 5 & 65535;
				const rt = w & 31;
				if (this.sysReg && this.sysReg(this, isRead, key, rt)) return;
				if (isRead) {
					if (key === 55824) this.wx(rt, BigInt(this.nzcv));
					else if (key === 56962) this.wx(rt, this.tpidr);
					else if (key === 57090) this.wx(rt, this.cntvct());
					else if (key === 55303) this.wx(rt, 4n);
					else throw new Error(`未知 MRS 系统寄存器 0x${key.toString(16)}`);
				} else if (key === 55824) this.nzcv = Number(this.rx(rt) & 15n);
				else if (key === 23457) {
					const a = Math.floor(Number(this.rx(rt)) / 64) * 64;
					for (let i = 0; i < 64; i += 8) this.st(a + i, 8, 0n);
				} else throw new Error(`未知 MSR 系统寄存器 0x${key.toString(16)}`);
				return;
			}
			case 1:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8: return;
			case 24: {
				const bytes = 1 << (w >>> 30);
				const addr = Number(this.rx(w >>> 5 & 31));
				this.wx(w & 31, this.ld(addr, bytes));
				return;
			}
			case 86:
			case 26: {
				const bytes = 1 << (w >>> 30);
				const addr = Number(this.rx(w >>> 5 & 31));
				this.wx(w & 31, this.ld(addr, bytes));
				this.monAddr = addr;
				this.monSize = bytes;
				return;
			}
			case 25: {
				const bytes = 1 << (w >>> 30);
				const addr = Number(this.rx(w >>> 5 & 31));
				this.st(addr, bytes, this.rx(w & 31));
				return;
			}
			case 87:
			case 27: {
				const bytes = 1 << (w >>> 30);
				const addr = Number(this.rx(w >>> 5 & 31));
				const ok = this.monAddr === addr && this.monSize === bytes;
				if (ok) {
					this.st(addr, bytes, this.rx(w & 31));
					this.monAddr = -1;
					this.monSize = 0;
				}
				this.wx(w >>> 16 & 31, ok ? 0n : 1n);
				return;
			}
			case 28: {
				const opc = w >>> 30;
				const V = w >>> 26 & 1;
				const idx = w >>> 23 & 3;
				const scale = V === 1 ? 4 << opc : opc === 2 ? 8 : 4;
				const imm = BigInt.asIntN(7, BigInt(w >>> 15 & 127)) * BigInt(scale);
				this.ldstPair(w, w >>> 5 & 31, imm, idx);
				return;
			}
			case 29: {
				const imm12 = w >>> 10 & 4095;
				const addr = Number(this.rxn(w >>> 5 & 31)) + imm12 * this.ldstBytes(w);
				this.ldstOne(w, addr);
				return;
			}
			case 30: {
				const size = w >>> 30;
				const Rm = w >>> 16 & 31;
				const option = w >>> 13 & 7;
				const S = w >>> 12 & 1;
				const bytes = this.ldstBytes(w);
				const shift = S === 1 ? bytes === 16 ? 4 : size : 0;
				const off = this.extendReg(this.rx(Rm), option, shift, 1);
				const addr = Number(this.rxn(w >>> 5 & 31) + off & MASK64);
				this.ldstOne(w, addr);
				return;
			}
			case 31: {
				const imm = Number(BigInt.asIntN(9, BigInt(w >>> 12 & 511)));
				const addr = Number(this.rxn(w >>> 5 & 31)) + imm;
				this.ldstOne(w, addr);
				return;
			}
			case 32: {
				const rn = w >>> 5 & 31;
				const imm = Number(BigInt.asIntN(9, BigInt(w >>> 12 & 511)));
				const base = Number(this.rxn(rn));
				this.ldstOne(w, base);
				this.wxn(rn, BigInt(base + imm));
				return;
			}
			case 33: {
				const rn = w >>> 5 & 31;
				const imm = Number(BigInt.asIntN(9, BigInt(w >>> 12 & 511)));
				const base = Number(this.rxn(rn)) + imm;
				this.wxn(rn, BigInt(base));
				this.ldstOne(w, base);
				return;
			}
			case 34: {
				const opc = w >>> 30;
				const V = w >>> 26 & 1;
				const off = BigInt.asIntN(19, BigInt(w >>> 5 & 524287)) << 2n;
				const addr = Number(BigInt(this.pc - 4) + off);
				const rt = w & 31;
				if (opc === 3) return;
				if (V === 1) {
					if (opc === 2) {
						this.setVlo(rt, this.ld(addr, 8));
						this.setVhi(rt, this.ld(addr + 8, 8));
					} else {
						this.setVlo(rt, this.ld(addr, opc === 1 ? 8 : 4));
						this.setVhi(rt, 0n);
					}
					return;
				}
				if (opc === 2) this.wx(rt, BigInt.asUintN(64, BigInt.asIntN(32, this.ld(addr, 4))));
				else this.wx(rt, this.ld(addr, opc === 1 ? 8 : 4));
				return;
			}
			case 35: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const S = w >>> 29 & 1;
				const shift = w >>> 22 & 3;
				const imm6 = w >>> 10 & 63;
				const b = this.shiftReg(this.rx(w >>> 16 & 31), shift, imm6, sf);
				const r = this.addsub(this.rx(w >>> 5 & 31), b, op === 1, sf, S === 1);
				if (S === 1) this.wx(w & 31, r);
				else this.wxn(w & 31, r);
				return;
			}
			case 36: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const S = w >>> 29 & 1;
				const opt = w >>> 13 & 7;
				const imm3 = w >>> 10 & 7;
				const b = this.extendReg(this.rx(w >>> 16 & 31), opt, imm3, sf);
				const r = this.addsub(this.rx(w >>> 5 & 31), b, op === 1, sf, S === 1);
				if (S === 1) this.wx(w & 31, r);
				else this.wxn(w & 31, r);
				return;
			}
			case 37: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const shift = w >>> 22 & 3;
				const N = w >>> 21 & 1;
				const imm6 = w >>> 10 & 63;
				const M = sf ? MASK64 : MASK32;
				let b = this.shiftReg(this.rx(w >>> 16 & 31), shift, imm6, sf);
				if (N === 1) b = ~b & M;
				const a = this.rx(w >>> 5 & 31);
				let r;
				if (opc === 0) r = a & b;
				else if (opc === 1) r = a | b;
				else if (opc === 2) r = a ^ b;
				else r = a & b;
				r &= M;
				if (opc === 3) {
					this.nzcv = this.nz(r, sf);
					this.wx(w & 31, r);
				} else this.wxn(w & 31, r);
				return;
			}
			case 38: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const S = w >>> 29 & 1;
				const M = sf ? MASK64 : MASK32;
				const signBit = sf ? 1n << 63n : 1n << 31n;
				const a = this.rx(w >>> 5 & 31) & M;
				let b = this.rx(w >>> 16 & 31) & M;
				if (op === 1) b = ~b & M;
				const cy = (this.nzcv & 2) !== 0 ? 1n : 0n;
				const sum = a + b + cy;
				const r = sum & M;
				if (S === 1) {
					const c = sum > M ? 2 : 0;
					const v = (~(a ^ b) & (a ^ r) & signBit) !== 0n ? 1 : 0;
					this.nzcv = this.nz(r, sf) | c | v;
				}
				if (S === 1) this.wx(w & 31, r);
				else this.wxn(w & 31, r);
				return;
			}
			case 39: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const Rm = w >>> 16 & 31;
				const cond = w >>> 12 & 15;
				const op2 = w >>> 10 & 3;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const M = sf ? MASK64 : MASK32;
				let r;
				if (this.cond(cond)) r = this.rx(rn) & M;
				else {
					r = this.rx(Rm) & M;
					if (op === 0) {
						if (op2 === 1) r = r + 1n & M;
					} else if (op2 === 0) r = ~r & M;
					else r = ~r + 1n & M;
				}
				this.wxn(rd, r);
				return;
			}
			case 40:
			case 41: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const cond = w >>> 12 & 15;
				const nzcvImm = w & 15;
				if (!this.cond(cond)) {
					this.nzcv = nzcvImm;
					return;
				}
				const M = sf ? MASK64 : MASK32;
				const a = this.rx(w >>> 5 & 31) & M;
				const b = c === 40 ? this.rx(w >>> 16 & 31) & M : BigInt(w >>> 16 & 31);
				this.addsub(a, b, op === 1, sf, true);
				return;
			}
			case 43: {
				const sf = w >>> 31;
				const opcode = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const M = sf ? MASK64 : MASK32;
				const bits = sf ? 64 : 32;
				const a = this.rx(rn) & M;
				let r;
				switch (opcode) {
					case 0:
						r = 0n;
						for (let i = 0; i < bits; i++) r |= (a >> BigInt(i) & 1n) << BigInt(bits - 1 - i);
						break;
					case 1:
						r = 0n;
						for (let i = 0; i < bits; i += 16) {
							const h = a >> BigInt(i) & 65535n;
							r |= ((h & 255n) << 8n | h >> 8n) << BigInt(i);
						}
						break;
					case 2:
						r = 0n;
						for (let i = 0; i < bits; i += 32) {
							const q = a >> BigInt(i) & MASK32;
							r |= ((q & 255n) << 24n | (q >> 8n & 255n) << 16n | (q >> 16n & 255n) << 8n | q >> 24n & 255n) << BigInt(i);
						}
						break;
					case 3:
						r = 0n;
						for (let i = 0; i < bits; i += 8) r |= (a >> BigInt(i) & 255n) << BigInt(bits - 8 - i);
						break;
					case 4:
						r = BigInt(bits - (a === 0n ? 0 : a.toString(2).length));
						break;
					default: {
						const signed = BigInt.asIntN(bits, a);
						const abs = signed < 0n ? ~signed : signed;
						const lead = bits - (abs === 0n ? 0 : abs.toString(2).length);
						r = BigInt(lead - 1 < 0 ? 0 : lead - 1);
						break;
					}
				}
				this.wx(rd, r & M);
				return;
			}
			case 42: {
				const sf = w >>> 31;
				const Rm = w >>> 16 & 31;
				const opcode = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const M = sf ? MASK64 : MASK32;
				const bits = sf ? 64 : 32;
				const a = this.rx(rn) & M;
				const b = this.rx(Rm) & M;
				let r;
				switch (opcode) {
					case 2:
						r = b === 0n ? 0n : a / b;
						break;
					case 3:
						if (b === 0n) r = 0n;
						else {
							const sa = BigInt.asIntN(bits, a);
							const sb = BigInt.asIntN(bits, b);
							r = BigInt.asUintN(bits, sa / sb);
						}
						break;
					case 8:
						r = this.shiftReg(a, 0, Number(b & BigInt(bits - 1)), sf);
						break;
					case 9:
						r = this.shiftReg(a, 1, Number(b & BigInt(bits - 1)), sf);
						break;
					case 10:
						r = this.shiftReg(a, 2, Number(b & BigInt(bits - 1)), sf);
						break;
					case 11:
						r = this.shiftReg(a, 3, Number(b & BigInt(bits - 1)), sf);
						break;
					default: throw new Error(`未知 dp2 opcode ${opcode}`);
				}
				this.wx(rd, r & M);
				return;
			}
			case 44: {
				const sf = w >>> 31;
				const Rm = w >>> 16 & 31;
				const op31 = w >>> 21 & 7;
				const o0 = w >>> 15 & 1;
				const Ra = w >>> 10 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const a = this.rx(rn);
				const b = this.rx(Rm);
				const acc = this.rx(Ra);
				let r;
				if (op31 === 0) {
					const p = a * b;
					r = o0 === 1 ? acc - p : acc + p;
					r &= sf ? MASK64 : MASK32;
				} else if (op31 === 1) {
					const p = BigInt.asIntN(32, a) * BigInt.asIntN(32, b);
					r = (o0 === 1 ? acc - p : acc + p) & MASK64;
				} else if (op31 === 2) {
					r = BigInt.asIntN(64, a) * BigInt.asIntN(64, b) >> 64n;
					r &= MASK64;
				} else if (op31 === 5) {
					const p = (a & MASK32) * (b & MASK32);
					r = (o0 === 1 ? acc - p : acc + p) & MASK64;
				} else if (op31 === 6) {
					r = (a & MASK64) * (b & MASK64) >> 64n;
					r &= MASK64;
				} else throw new Error(`未知 dp3 op31 ${op31}`);
				this.wx(rd, r);
				return;
			}
			case 45: {
				const type = w >>> 22 & 3;
				const rd = w & 31;
				const bits = this.vfpExpand(w >>> 13 & 255, type === 0);
				this.setVlo(rd, bits);
				this.setVhi(rd, 0n);
				return;
			}
			case 46: {
				const rn = w >>> 5 & 31;
				this.wx(w & 31, this.vlo(rn) & MASK32);
				return;
			}
			case 47: {
				const rn = w >>> 5 & 31;
				this.wx(w & 31, this.vlo(rn));
				return;
			}
			case 48: {
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				this.setVlo(rd, this.rx(rn) & MASK32);
				this.setVhi(rd, 0n);
				return;
			}
			case 49: {
				const rn = w >>> 5 & 31;
				this.setVlo(w & 31, this.rx(rn));
				this.setVhi(w & 31, 0n);
				return;
			}
			case 50:
				this.setVlo(w & 31, this.vlo(w >>> 5 & 31));
				this.setVhi(w & 31, 0n);
				return;
			case 51: {
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				this.setVlo(rd, this.vlo(rn) & MASK32);
				this.setVhi(rd, 0n);
				return;
			}
			case 52: {
				const rn = w >>> 5 & 31;
				this.setF64(w & 31, Math.abs(this.getF64(rn)));
				return;
			}
			case 53: {
				const rn = w >>> 5 & 31;
				this.setF32(w & 31, Math.abs(this.getF32(rn)));
				return;
			}
			case 103:
				this.setVlo(w & 31, this.vlo(w >>> 5 & 31) ^ 9223372036854775808n);
				this.setVhi(w & 31, 0n);
				return;
			case 104: {
				const rn = w >>> 5 & 31;
				this.setVlo(w & 31, this.vlo(rn) & MASK32 ^ 2147483648n);
				this.setVhi(w & 31, 0n);
				return;
			}
			case 105:
				this.setF64(w & 31, Math.sqrt(this.getF64(w >>> 5 & 31)));
				return;
			case 106:
				this.setF32(w & 31, Math.sqrt(this.getF32(w >>> 5 & 31)));
				return;
			case 54: {
				const a = this.getF64(w >>> 5 & 31);
				const b = this.getF64(w >>> 16 & 31);
				this.setF64(w & 31, Math.abs(a - b));
				return;
			}
			case 55: {
				const a = this.getF32(w >>> 5 & 31);
				const b = this.getF32(w >>> 16 & 31);
				this.setF32(w & 31, Math.abs(a - b));
				return;
			}
			case 56: {
				const a = this.getF64(w >>> 5 & 31);
				const b = this.getF64(w >>> 16 & 31);
				this.setF64(w & 31, a * b);
				return;
			}
			case 57: {
				const a = this.getF32(w >>> 5 & 31);
				const b = this.getF32(w >>> 16 & 31);
				this.setF32(w & 31, a * b);
				return;
			}
			case 89: {
				const a = this.getF64(w >>> 5 & 31);
				const b = this.getF64(w >>> 16 & 31);
				this.setF64(w & 31, a + b);
				return;
			}
			case 90: {
				const a = this.getF32(w >>> 5 & 31);
				const b = this.getF32(w >>> 16 & 31);
				this.setF32(w & 31, a + b);
				return;
			}
			case 91: {
				const a = this.getF64(w >>> 5 & 31);
				const b = this.getF64(w >>> 16 & 31);
				this.setF64(w & 31, a - b);
				return;
			}
			case 92: {
				const a = this.getF32(w >>> 5 & 31);
				const b = this.getF32(w >>> 16 & 31);
				this.setF32(w & 31, a - b);
				return;
			}
			case 93: {
				const a = this.getF64(w >>> 5 & 31);
				const b = this.getF64(w >>> 16 & 31);
				this.setF64(w & 31, a / b);
				return;
			}
			case 94: {
				const a = this.getF32(w >>> 5 & 31);
				const b = this.getF32(w >>> 16 & 31);
				this.setF32(w & 31, a / b);
				return;
			}
			case 95: {
				const n = this.getF64(w >>> 5 & 31);
				const m = this.getF64(w >>> 16 & 31);
				const a = this.getF64(w >>> 10 & 31);
				this.setF64(w & 31, n * m + a);
				return;
			}
			case 96: {
				const n = this.getF32(w >>> 5 & 31);
				const m = this.getF32(w >>> 16 & 31);
				const a = this.getF32(w >>> 10 & 31);
				this.setF32(w & 31, n * m + a);
				return;
			}
			case 97: {
				const n = this.getF64(w >>> 5 & 31);
				const m = this.getF64(w >>> 16 & 31);
				const a = this.getF64(w >>> 10 & 31);
				this.setF64(w & 31, a - n * m);
				return;
			}
			case 98: {
				const n = this.getF32(w >>> 5 & 31);
				const m = this.getF32(w >>> 16 & 31);
				const a = this.getF32(w >>> 10 & 31);
				this.setF32(w & 31, a - n * m);
				return;
			}
			case 99: {
				const n = this.getF64(w >>> 5 & 31);
				const m = this.getF64(w >>> 16 & 31);
				const a = this.getF64(w >>> 10 & 31);
				this.setF64(w & 31, -a - n * m);
				return;
			}
			case 100: {
				const n = this.getF32(w >>> 5 & 31);
				const m = this.getF32(w >>> 16 & 31);
				const a = this.getF32(w >>> 10 & 31);
				this.setF32(w & 31, -a - n * m);
				return;
			}
			case 101: {
				const n = this.getF64(w >>> 5 & 31);
				const m = this.getF64(w >>> 16 & 31);
				const a = this.getF64(w >>> 10 & 31);
				this.setF64(w & 31, n * m - a);
				return;
			}
			case 102: {
				const n = this.getF32(w >>> 5 & 31);
				const m = this.getF32(w >>> 16 & 31);
				const a = this.getF32(w >>> 10 & 31);
				this.setF32(w & 31, n * m - a);
				return;
			}
			case 58:
				this.fpCompare(this.getF64(w >>> 5 & 31), this.getF64(w >>> 16 & 31));
				return;
			case 59:
				this.fpCompare(this.getF32(w >>> 5 & 31), this.getF32(w >>> 16 & 31));
				return;
			case 60:
				this.fpCompare(this.getF64(w >>> 5 & 31), 0);
				return;
			case 61:
				this.fpCompare(this.getF32(w >>> 5 & 31), 0);
				return;
			case 62: {
				const cond = w >>> 12 & 15;
				const rn = w >>> 5 & 31;
				const rm = w >>> 16 & 31;
				this.setF64(w & 31, this.cond(cond) ? this.getF64(rn) : this.getF64(rm));
				return;
			}
			case 63: {
				const cond = w >>> 12 & 15;
				const rn = w >>> 5 & 31;
				const rm = w >>> 16 & 31;
				this.setF32(w & 31, this.cond(cond) ? this.getF32(rn) : this.getF32(rm));
				return;
			}
			case 64: {
				const cond = w >>> 12 & 15;
				if (this.cond(cond)) this.fpCompare(this.getF64(w >>> 5 & 31), this.getF64(w >>> 16 & 31));
				else this.nzcv = w & 15;
				return;
			}
			case 65: {
				const cond = w >>> 12 & 15;
				if (this.cond(cond)) this.fpCompare(this.getF32(w >>> 5 & 31), this.getF32(w >>> 16 & 31));
				else this.nzcv = w & 15;
				return;
			}
			case 66: {
				const v = this.getF64(w >>> 5 & 31);
				let t = Math.trunc(v);
				if (!Number.isFinite(t)) t = v > 0 ? 2147483647 : v < 0 ? -2147483648 : 0;
				if (t > 2147483647) t = 2147483647;
				if (t < -2147483648) t = -2147483648;
				this.wx(w & 31, BigInt(t >>> 0));
				return;
			}
			case 67: {
				const v = this.getF64(w >>> 5 & 31);
				let t = BigInt(Math.trunc(v));
				if (!Number.isFinite(v)) t = v > 0 ? 9223372036854775807n : -9223372036854775808n;
				this.wx(w & 31, BigInt.asUintN(64, t));
				return;
			}
			case 114: {
				const v = this.getF64(w >>> 5 & 31);
				let t = Math.trunc(v);
				if (!Number.isFinite(t)) t = v > 0 ? 4294967295 : 0;
				if (t > 4294967295) t = 4294967295;
				if (t < 0) t = 0;
				this.wx(w & 31, BigInt(t));
				return;
			}
			case 115: {
				const v = this.getF64(w >>> 5 & 31);
				let t = Math.trunc(v);
				if (!Number.isFinite(t)) t = v > 0 ? 0x10000000000000000 : 0;
				if (t < 0) t = 0;
				this.wx(w & 31, BigInt(t));
				return;
			}
			case 116:
			case 117:
			case 118:
			case 119: {
				const rn = w >>> 5 & 31;
				const v = c === 117 || c === 119 ? this.getF64(rn) : this.getF32(rn);
				const x = c === 118 || c === 119;
				const t = Math.ceil(v);
				let big;
				if (!Number.isFinite(t)) big = v > 0 ? x ? 18446744073709551615n : 4294967295n : 0n;
				else if (t < 0) big = 0n;
				else {
					big = x ? BigInt(t) : BigInt(Math.min(t, 4294967295));
					if (big > 18446744073709551615n) big = 18446744073709551615n;
				}
				this.wx(w & 31, big);
				return;
			}
			case 68:
			case 70: {
				const rn = w >>> 5 & 31;
				const a = this.rx(rn) & MASK32;
				this.setF64(w & 31, c === 68 ? Number(BigInt.asIntN(32, a)) : Number(a));
				return;
			}
			case 69:
			case 71: {
				const rn = w >>> 5 & 31;
				const a = this.rx(rn);
				this.setF64(w & 31, c === 69 ? Number(BigInt.asIntN(64, a)) : Number(a));
				return;
			}
			case 72:
			case 73: {
				const rn = w >>> 5 & 31;
				const a = this.vlo(rn);
				this.setF64(w & 31, c === 72 ? Number(BigInt.asIntN(64, a)) : Number(a));
				return;
			}
			case 74:
			case 75: {
				const rn = w >>> 5 & 31;
				const a = this.vlo(rn) & MASK32;
				this.setF32(w & 31, c === 74 ? Number(BigInt.asIntN(32, a)) : Number(a));
				return;
			}
			case 108:
			case 109: {
				const rn = w >>> 5 & 31;
				const a = this.rx(rn) & MASK32;
				this.setF32(w & 31, c === 108 ? Number(BigInt.asIntN(32, a)) : Number(a));
				return;
			}
			case 110:
			case 111: {
				const rn = w >>> 5 & 31;
				const a = this.rx(rn);
				this.setF32(w & 31, c === 110 ? Number(BigInt.asIntN(64, a)) : Number(a));
				return;
			}
			case 76: {
				const Q = w >>> 30 & 1;
				const U = w >>> 29 & 1;
				const size = w >>> 22 & 3;
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const aLo = this.vlo(rn);
				const aHi = this.vhi(rn);
				const bLo = this.vlo(rm);
				const bHi = this.vhi(rm);
				const dLo = this.vlo(rd);
				const dHi = this.vhi(rd);
				const op = U << 2 | size;
				let lo;
				let hi;
				switch (op) {
					case 0:
						lo = aLo & bLo;
						hi = aHi & bHi;
						break;
					case 1:
						lo = aLo & ~bLo;
						hi = aHi & ~bHi;
						break;
					case 2:
						lo = aLo | bLo;
						hi = aHi | bHi;
						break;
					case 3:
						lo = aLo | ~bLo;
						hi = aHi | ~bHi;
						break;
					case 4:
						lo = aLo ^ bLo;
						hi = aHi ^ bHi;
						break;
					case 5:
					case 6:
						lo = aLo & bLo | ~aLo & dLo;
						hi = aHi & bHi | ~aHi & dHi;
						break;
					default:
						lo = aLo & dLo | ~aLo & bLo;
						hi = aHi & dHi | ~aHi & bHi;
				}
				this.setVlo(rd, lo & MASK64);
				this.setVhi(rd, Q === 1 ? hi & MASK64 : 0n);
				return;
			}
			case 112:
			case 113: {
				const Q = w >>> 30 & 1;
				const esize = 8 << (w >>> 22 & 3);
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const mask = (1n << BigInt(esize)) - 1n;
				const sub = c === 113;
				const calc = (a, b) => {
					let out = 0n;
					for (let bit = 0; bit < 64; bit += esize) {
						const sh = BigInt(bit);
						const x = a >> sh & mask;
						const y = b >> sh & mask;
						out |= ((sub ? x - y : x + y) & mask) << sh;
					}
					return out;
				};
				this.setVlo(rd, calc(this.vlo(rn), this.vlo(rm)));
				this.setVhi(rd, Q === 1 ? calc(this.vhi(rn), this.vhi(rm)) : 0n);
				return;
			}
			case 77: {
				const Q = w >>> 30 & 1;
				const { esize, index } = this.imm5ToLane(w >>> 16 & 31);
				const val = this.getLane(w >>> 5 & 31, index, esize);
				this.wx(w & 31, Q === 1 ? val : val & MASK32);
				return;
			}
			case 78: {
				const Q = w >>> 30 & 1;
				const { esize } = this.imm5ToLane(w >>> 16 & 31);
				const val = this.rx(w >>> 5 & 31) & (1n << BigInt(esize)) - 1n;
				const rd = w & 31;
				const lanes = (Q === 1 ? 128 : 64) / esize;
				let lo = 0n;
				let hi = 0n;
				for (let i = 0; i < lanes; i++) {
					const bit = i * esize;
					if (bit < 64) lo |= val << BigInt(bit);
					else hi |= val << BigInt(bit - 64);
				}
				this.setVlo(rd, lo);
				this.setVhi(rd, hi);
				return;
			}
			case 79: {
				const Q = w >>> 30 & 1;
				const { esize, index } = this.imm5ToLane(w >>> 16 & 31);
				const val = this.getLane(w >>> 5 & 31, index, esize);
				const rd = w & 31;
				const lanes = (Q === 1 ? 128 : 64) / esize;
				let lo = 0n;
				let hi = 0n;
				for (let i = 0; i < lanes; i++) {
					const bit = i * esize;
					if (bit < 64) lo |= val << BigInt(bit);
					else hi |= val << BigInt(bit - 64);
				}
				this.setVlo(rd, lo);
				this.setVhi(rd, hi);
				return;
			}
			case 80: {
				const Q = w >>> 30 & 1;
				const op = w >>> 29 & 1;
				const cmode = w >>> 12 & 15;
				const imm8 = (w >>> 16 & 7) << 5 | w >>> 5 & 31;
				const rd = w & 31;
				const t = MOVI_LANES[cmode * 2 + op];
				if (t !== void 0) {
					const [esize, shift, msl, inv] = t;
					const mask = (1n << BigInt(esize)) - 1n;
					let v = BigInt(imm8) << BigInt(shift) | (1n << BigInt(msl)) - 1n;
					if (inv === 1) v = ~v & mask;
					let lo = 0n;
					let hi = 0n;
					for (let bit = 0; bit < 64; bit += esize) {
						lo |= v << BigInt(bit);
						hi |= v << BigInt(bit);
					}
					this.setVlo(rd, lo);
					this.setVhi(rd, Q === 1 ? hi : 0n);
					return;
				}
				if (cmode === 15) {
					this.setVlo(rd, MASK64);
					this.setVhi(rd, Q === 1 ? MASK64 : 0n);
					return;
				}
				throw new Error(`未实现的 movi cmode=${cmode} op=${op}`);
			}
			case 81:
			case 82: {
				const Q = w >>> 30 & 1;
				const esize = 8 << (w >>> 22 & 3);
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const lanes = (Q === 1 ? 128 : 64) / esize;
				const half = lanes / 2;
				const zip = c === 81;
				const as = [];
				const bs = [];
				for (let i = 0; i < lanes; i++) {
					as.push(this.getLane(rn, i, esize));
					bs.push(this.getLane(rm, i, esize));
				}
				for (let i = 0; i < half; i++) if (zip) {
					this.setLane(rd, 2 * i, esize, as[i]);
					this.setLane(rd, 2 * i + 1, esize, bs[i]);
				} else {
					this.setLane(rd, i, esize, as[2 * i]);
					this.setLane(rd, half + i, esize, bs[2 * i]);
				}
				if (Q === 0) this.setVhi(rd, 0n);
				return;
			}
			case 83: {
				const Q = w >>> 30 & 1;
				const imm4 = w >>> 11 & 15;
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const a = this.vhi(rn) << 64n | this.vlo(rn);
				const r = ((this.vhi(rm) << 64n | this.vlo(rm)) << 128n | a) >> BigInt(imm4 * 8) & (1n << 128n) - 1n;
				this.setVlo(rd, r & MASK64);
				this.setVhi(rd, Q === 1 ? r >> 64n & MASK64 : 0n);
				return;
			}
			case 84: {
				const Q = w >>> 30 & 1;
				const esize = 8 << (w >>> 22 & 3);
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const lanes = (Q === 1 ? 128 : 64) / esize;
				const mask = (1n << BigInt(esize)) - 1n;
				const as = [];
				const bs = [];
				for (let i = 0; i < lanes; i++) {
					as.push(this.getLane(rn, i, esize));
					bs.push(this.getLane(rm, i, esize));
				}
				for (let i = 0; i < lanes; i++) {
					const a = as[i];
					const sh = BigInt.asIntN(esize, bs[i]);
					const lim = BigInt(esize);
					let r;
					if (sh >= lim || sh <= -lim) r = 0n;
					else if (sh >= 0n) r = a << sh & mask;
					else if (c === 84) r = a >> -sh;
					else r = BigInt.asUintN(esize, BigInt.asIntN(esize, a) >> -sh);
					this.setLane(rd, i, esize, r);
				}
				if (Q === 0) this.setVhi(rd, 0n);
				return;
			}
			case 88: {
				const imm = w >>> 16 & 255;
				if (imm === 0) throw new Error("非法 shl 立即数");
				const esize = 8 << 31 - Math.clz32(imm) - 3;
				const shift = imm - esize;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const mask = (1n << BigInt(esize)) - 1n;
				this.setLane(rd, 0, esize, this.getLane(rn, 0, esize) << BigInt(shift) & mask);
				this.setVhi(rd, 0n);
				return;
			}
			case 107: {
				const Q = w >>> 30 & 1;
				const imm = w >>> 16 & 255;
				if (imm === 0) throw new Error("非法 shl 立即数");
				const esize = 8 << 31 - Math.clz32(imm) - 3;
				const shift = BigInt(imm - esize);
				const lanes = (Q === 1 ? 128 : 64) / esize;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const mask = (1n << BigInt(esize)) - 1n;
				for (let i = 0; i < lanes; i++) this.setLane(rd, i, esize, this.getLane(rn, i, esize) << shift & mask);
				return;
			}
			case 85: {
				const Q = w >>> 30 & 1;
				const U = w >>> 29 & 1;
				const immh = w >>> 19 & 15;
				if (immh === 0) throw new Error("非法 sshll 立即数");
				const size = 31 - Math.clz32(immh);
				const esize = 8 << size;
				const shift = (w >>> 16 & 127) - (8 << size);
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const lanes = 128 / (esize * 2);
				const srcBase = Q === 1 ? 64 / esize : 0;
				const vals = [];
				for (let i = 0; i < lanes; i++) vals.push(this.getLane(rn, srcBase + i, esize));
				for (let i = 0; i < lanes; i++) {
					const a = vals[i];
					const v = U === 1 ? a & (1n << BigInt(esize)) - 1n : BigInt.asUintN(esize * 2, BigInt.asIntN(esize, a));
					this.setLane(rd, i, esize * 2, v << BigInt(shift));
				}
				return;
			}
			case 120: {
				const Q = w >>> 30 & 1;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const lanes = Q === 1 ? 16 : 8;
				let lo = 0n;
				let hi = 0n;
				for (let i = 0; i < lanes; i++) {
					let b = Number(this.getLane(rn, i, 8));
					let n = 0;
					while (b !== 0) {
						n += b & 1;
						b >>>= 1;
					}
					if (i < 8) lo |= BigInt(n) << BigInt(i * 8);
					else hi |= BigInt(n) << BigInt((i - 8) * 8);
				}
				this.setVlo(rd, lo);
				this.setVhi(rd, hi);
				return;
			}
			case 121: {
				const Q = w >>> 30 & 1;
				const U = w >>> 29 & 1;
				const esize = 8 << (w >>> 22 & 3);
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const lanes = (Q === 1 ? 128 : 64) / esize;
				let sum = 0n;
				for (let i = 0; i < lanes; i++) {
					const e = this.getLane(rn, i, esize);
					sum += U === 1 ? e : BigInt.asIntN(esize, e);
				}
				this.setVlo(rd, sum & MASK64);
				this.setVhi(rd, 0n);
				return;
			}
			default: throw new Error(`未实现指令 0x${w.toString(16).padStart(8, "0")} (class=${c}) @0x${(this.pc - 4).toString(16)}`);
		}
	}
};
//#endregion
//#region src/app/so/mem.ts
/**
* AArch64 解释器使用的线性内存。
*
* 地址用 number（被测 so 的映射全部落在 0x4000_0000 ~ 0xfffd_ffff，远小于 2^53），
* 按 64 KiB 分页存放，未映射页访问直接抛错——这是发现「加载不全」最有效的手段。
*/
const PAGE_BITS = 16;
const PAGE_SIZE = 65536;
const PAGE_OFF = 65535;
var PageMem = class {
	/** 页表：下标 = addr >>> 16（稀疏数组，未分配为 undefined；JIT 直接读它） */
	pt = [];
	/** 与 pt 平行的 DataView 视图（JIT 用：多字节访存比逐字节拼装快一倍） */
	dv = [];
	/** 已映射区间 [lo, hi)，页在首次访问时按需分配（避免一次性分配上百 MB） */
	rlo = [];
	rhi = [];
	/** 最近访问的页缓存（取指/读写绝大多数命中同一页） */
	lastIdx = -1;
	lastPage = null;
	/** 调试用写监视（只在设置时生效） */
	watch = null;
	/** 调试用写监视 2（与 watch 并行，互不覆盖） */
	watch2 = null;
	/** 调试用写监视 3（仅作门控触发用） */
	watch3 = null;
	/** 调试用读监视（只在设置时生效） */
	watchRead = null;
	/** 调试：写日志（4 元组 addr,size,lo,hi），对拍用 */
	wlog = null;
	/** 分配 [base, base+size)（已存在则保留原内容；页按需分配） */
	map(base, size) {
		const b = base >>> 0;
		const lo = b - b % PAGE_SIZE;
		const end = b + Math.max(0, size);
		const hi = Math.ceil(end / PAGE_SIZE) * PAGE_SIZE;
		for (let i = 0; i < this.rlo.length; i++) if (lo >= this.rlo[i] && hi <= this.rhi[i]) return;
		this.rlo.push(lo);
		this.rhi.push(hi);
	}
	inRange(addr) {
		const rlo = this.rlo;
		const rhi = this.rhi;
		for (let i = 0; i < rlo.length; i++) if (addr >= rlo[i] && addr < rhi[i]) return true;
		return false;
	}
	/** 把 data 写入 base 起（自动分配页，按页批量拷贝） */
	load(base, data) {
		this.map(base, data.length);
		let off = 0;
		while (off < data.length) {
			const a = base + off;
			const page = this.page(a);
			const pageOff = a & PAGE_OFF;
			const n = Math.min(PAGE_SIZE - pageOff, data.length - off);
			page.set(data.subarray(off, off + n), pageOff);
			off += n;
		}
	}
	/** 拷贝一段出来（调试/对拍用） */
	slice(base, size) {
		const out = new Uint8Array(size);
		for (let i = 0; i < size; i++) {
			const a = base + i;
			out[i] = this.page(a)[a & PAGE_OFF];
		}
		return out;
	}
	/** 等价 memmove：把 [src, src+n) 拷到 dst（允许重叠） */
	copy(dst, src, n) {
		if (n <= 0 || dst === src) return;
		if (dst < src || dst >= src + n) {
			let off = 0;
			while (off < n) {
				const s = src + off;
				const d = dst + off;
				const sp = this.page(s);
				const dp = this.page(d);
				const so = s & PAGE_OFF;
				const dofs = d & PAGE_OFF;
				const k = Math.min(PAGE_SIZE - so, PAGE_SIZE - dofs, n - off);
				dp.set(sp.subarray(so, so + k), dofs);
				off += k;
			}
			return;
		}
		const tmp = this.slice(src, n);
		this.load(dst, tmp);
	}
	/** 等价 memset */
	fill(dst, v, n) {
		const b = v & 255;
		let off = 0;
		while (off < n) {
			const d = dst + off;
			const dp = this.page(d);
			const dofs = d & PAGE_OFF;
			const k = Math.min(PAGE_SIZE - dofs, n - off);
			dp.fill(b, dofs, dofs + k);
			off += k;
		}
	}
	/** 取页并确保已分配（未映射则抛错）；JIT 的慢路径也走它 */
	mkpage(addr) {
		const idx = addr >>> PAGE_BITS;
		let p = this.pt[idx];
		if (p === void 0) {
			if (!this.inRange(addr)) throw new Error(`访问未映射地址 0x${(addr >>> 0).toString(16)}`);
			p = new Uint8Array(PAGE_SIZE);
			this.pt[idx] = p;
			this.dv[idx] = new DataView(p.buffer);
		}
		this.lastIdx = idx;
		this.lastPage = p;
		return p;
	}
	/** 取页的 DataView（未分配则分配）；JIT 快路径用 */
	mkdv(addr) {
		const p = this.mkpage(addr);
		const idx = addr >>> PAGE_BITS;
		let d = this.dv[idx];
		if (d === void 0) {
			d = new DataView(p.buffer);
			this.dv[idx] = d;
		}
		return d;
	}
	page(addr) {
		if (addr >>> PAGE_BITS === this.lastIdx) return this.lastPage;
		return this.mkpage(addr);
	}
	/** 页被外部重建/回收后清掉「最近一页」缓存（快照恢复用） */
	invalidate() {
		this.lastIdx = -1;
		this.lastPage = null;
	}
	fetch(addr) {
		const off = addr & PAGE_OFF;
		if (off + 4 <= PAGE_SIZE) {
			const idx = addr >>> PAGE_BITS;
			let p;
			if (idx === this.lastIdx) p = this.lastPage;
			else {
				const q = this.pt[idx];
				if (q === void 0) {
					if (!this.inRange(addr)) throw new Error(`取指未映射地址 0x${(addr >>> 0).toString(16)}`);
					p = new Uint8Array(PAGE_SIZE);
					this.pt[idx] = p;
				} else p = q;
				this.lastIdx = idx;
				this.lastPage = p;
			}
			return (p[off] | p[off + 1] << 8 | p[off + 2] << 16 | p[off + 3] << 24) >>> 0;
		}
		return Number(this.readRaw(addr, 4));
	}
	read(addr, size) {
		const v = this.readRaw(addr, size);
		const w = this.watchRead;
		if (w !== null) w.cb(addr, size, v);
		return v;
	}
	readRaw(addr, size) {
		const off = addr & PAGE_OFF;
		if (off + size <= PAGE_SIZE) {
			const p = this.page(addr);
			switch (size) {
				case 1: return BigInt(p[off]);
				case 2: return BigInt(p[off] | p[off + 1] << 8);
				case 4: return BigInt((p[off] | p[off + 1] << 8 | p[off + 2] << 16 | p[off + 3] << 24) >>> 0);
				default: {
					const lo = (p[off] | p[off + 1] << 8 | p[off + 2] << 16 | p[off + 3] << 24) >>> 0;
					const hi = (p[off + 4] | p[off + 5] << 8 | p[off + 6] << 16 | p[off + 7] << 24) >>> 0;
					return BigInt(hi) << 32n | BigInt(lo);
				}
			}
		}
		let v = 0n;
		for (let i = 0; i < size; i++) {
			const a = addr + i;
			v |= BigInt(this.page(a)[a & PAGE_OFF]) << BigInt(i * 8);
		}
		return v;
	}
	write(addr, size, v) {
		const w = this.watch;
		if (w !== null && addr < w.hi && addr + size > w.lo) w.cb(addr, size, v);
		const w2 = this.watch2;
		if (w2 !== null && addr < w2.hi && addr + size > w2.lo) w2.cb(addr, size, v);
		const w3 = this.watch3;
		if (w3 !== null && addr < w3.hi && addr + size > w3.lo) w3.cb(addr, size, v);
		const lg = this.wlog;
		if (lg !== null) lg.push(addr, size, Number(v & 4294967295n) | 0, Number(v >> 32n & 4294967295n) | 0);
		const off = addr & PAGE_OFF;
		if (off + size <= PAGE_SIZE) {
			const p = this.page(addr);
			switch (size) {
				case 1:
					p[off] = Number(v & 255n);
					return;
				case 2:
					p[off] = Number(v & 255n);
					p[off + 1] = Number(v >> 8n & 255n);
					return;
				case 4: {
					const x = Number(v & 4294967295n);
					p[off] = x & 255;
					p[off + 1] = x >>> 8 & 255;
					p[off + 2] = x >>> 16 & 255;
					p[off + 3] = x >>> 24 & 255;
					return;
				}
				default: {
					const lo = Number(v & 4294967295n);
					const hi = Number(v >> 32n & 4294967295n);
					p[off] = lo & 255;
					p[off + 1] = lo >>> 8 & 255;
					p[off + 2] = lo >>> 16 & 255;
					p[off + 3] = lo >>> 24 & 255;
					p[off + 4] = hi & 255;
					p[off + 5] = hi >>> 8 & 255;
					p[off + 6] = hi >>> 16 & 255;
					p[off + 7] = hi >>> 24 & 255;
					return;
				}
			}
		}
		for (let i = 0; i < size; i++) {
			const a = addr + i;
			this.page(a)[a & PAGE_OFF] = Number(v >> BigInt(i * 8) & 255n);
		}
	}
	/** 读 C 字符串（调试用） */
	cstr(addr, limit = 4096) {
		const out = [];
		for (let i = 0; i < limit; i++) {
			const b = Number(this.read(addr + i, 1));
			if (b === 0) break;
			out.push(b);
		}
		return Buffer.from(out).toString("utf8");
	}
	ld8(addr) {
		return this.page(addr)[addr & PAGE_OFF];
	}
	ld16(addr) {
		const o = addr & PAGE_OFF;
		if (o + 2 > PAGE_SIZE) return Number(this.readRaw(addr, 2));
		const p = this.page(addr);
		return p[o] | p[o + 1] << 8;
	}
	ld32(addr) {
		const o = addr & PAGE_OFF;
		if (o + 4 > PAGE_SIZE) return Number(this.readRaw(addr, 4)) | 0;
		const p = this.page(addr);
		return p[o] | p[o + 1] << 8 | p[o + 2] << 16 | p[o + 3] << 24 | 0;
	}
	/** 64 位读：返回低 32 位，高 32 位写入 out[0] */
	ld64(addr, out) {
		const o = addr & PAGE_OFF;
		if (o + 8 > PAGE_SIZE) {
			const v = this.readRaw(addr, 8);
			out[0] = Number(v >> 32n & 4294967295n);
			return Number(v & 4294967295n) | 0;
		}
		const p = this.page(addr);
		out[0] = p[o + 4] | p[o + 5] << 8 | p[o + 6] << 16 | p[o + 7] << 24 | 0;
		return p[o] | p[o + 1] << 8 | p[o + 2] << 16 | p[o + 3] << 24 | 0;
	}
	st8(addr, v) {
		const lg = this.wlog;
		if (lg !== null) lg.push(addr, 1, v & 255, 0);
		this.page(addr)[addr & PAGE_OFF] = v & 255;
	}
	st16(addr, v) {
		const o = addr & PAGE_OFF;
		if (o + 2 > PAGE_SIZE) {
			this.write(addr, 2, BigInt(v & 65535));
			return;
		}
		const lg = this.wlog;
		if (lg !== null) lg.push(addr, 2, v & 65535, 0);
		const p = this.page(addr);
		p[o] = v & 255;
		p[o + 1] = v >>> 8 & 255;
	}
	st32(addr, v) {
		const o = addr & PAGE_OFF;
		if (o + 4 > PAGE_SIZE) {
			this.write(addr, 4, BigInt(v >>> 0));
			return;
		}
		const lg = this.wlog;
		if (lg !== null) lg.push(addr, 4, v | 0, 0);
		const p = this.page(addr);
		p[o] = v & 255;
		p[o + 1] = v >>> 8 & 255;
		p[o + 2] = v >>> 16 & 255;
		p[o + 3] = v >>> 24 & 255;
	}
	st64(addr, lo, hi) {
		const o = addr & PAGE_OFF;
		if (o + 8 > PAGE_SIZE) {
			this.write(addr, 8, BigInt(hi >>> 0) << 32n | BigInt(lo >>> 0));
			return;
		}
		const lg = this.wlog;
		if (lg !== null) lg.push(addr, 8, lo, hi);
		const p = this.page(addr);
		p[o] = lo & 255;
		p[o + 1] = lo >>> 8 & 255;
		p[o + 2] = lo >>> 16 & 255;
		p[o + 3] = lo >>> 24 & 255;
		p[o + 4] = hi & 255;
		p[o + 5] = hi >>> 8 & 255;
		p[o + 6] = hi >>> 16 & 255;
		p[o + 7] = hi >>> 24 & 255;
	}
};
//#endregion
//#region src/app/so/elf.ts
/**
* 最小 ELF64 (AArch64) 解析/加载器：只覆盖「从 .so 冷启动」需要的部分。
*
* 与 unidbg 的行为对齐：
* - 按 64 KiB 粒度映射每个 PT_LOAD（unidbg 的内存快照正是 64K 对齐切分的）；
* - 导出表取 .dynsym 里已定义的 GLOBAL/WEAK 符号（st_value != 0）；
* - 重定位只处理 AArch64 的 ABS64 / GLOB_DAT / JUMP_SLOT / RELATIVE。
*/
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_PLTRELSZ = 2;
const DT_HASH = 4;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_RELA = 7;
const DT_RELASZ = 8;
const DT_SONAME = 14;
const DT_PLTREL = 20;
const DT_JMPREL = 23;
const DT_INIT_ARRAY = 25;
const DT_FINI_ARRAY = 26;
const DT_INIT_ARRAYSZ = 27;
const DT_FINI_ARRAYSZ = 28;
const R_AARCH64_GLOB_DAT = 1025;
const R_AARCH64_JUMP_SLOT = 1026;
const R_AARCH64_RELATIVE = 1027;
/** 一个已解析的 ELF 镜像（未映射） */
var ElfImage = class {
	path;
	data;
	segments = [];
	exports = /* @__PURE__ */ new Map();
	symbols = [];
	relocs = [];
	/** .init_array / .fini_array 的虚拟地址与字节数（内容要等重定位后从内存读） */
	initArrayVa = 0;
	initArraySize = 0;
	finiArrayVa = 0;
	finiArraySize = 0;
	soname = "";
	needed = [];
	/** 最后一个 PT_LOAD 的 vaddr+memsz，再按 64 KiB 上取整 */
	extent = 0;
	constructor(path) {
		this.path = path;
		this.data = new Uint8Array(readFileSync(path));
		this.parse();
	}
	u16(o) {
		return this.data[o] | this.data[o + 1] << 8;
	}
	u32(o) {
		const d = this.data;
		return (d[o] | d[o + 1] << 8 | d[o + 2] << 16 | d[o + 3] << 24) >>> 0;
	}
	u64(o) {
		return Number(new DataView(this.data.buffer, this.data.byteOffset).getBigUint64(o, true));
	}
	i64(o) {
		return Number(new DataView(this.data.buffer, this.data.byteOffset).getBigInt64(o, true));
	}
	/** 虚拟地址 → 文件偏移（PT_LOAD 覆盖范围内） */
	vaToOff(va) {
		for (const s of this.segments) if (va >= s.vaddr && va < s.vaddr + s.filesz) return s.offset + (va - s.vaddr);
		throw new Error(`${this.path}: va 0x${va.toString(16)} 不在任何 PT_LOAD 内`);
	}
	cstr(off) {
		let e = off;
		while (this.data[e] !== 0) e += 1;
		return Buffer.from(this.data.subarray(off, e)).toString("utf8");
	}
	parse() {
		const d = this.data;
		if (this.u32(0) !== 1179403647) throw new Error(`${this.path}: 不是 ELF`);
		if (d[4] !== 2 || d[5] !== 1) throw new Error(`${this.path}: 只支持 ELF64 小端`);
		const phoff = this.u64(32);
		const phentsize = this.u16(54);
		const phnum = this.u16(56);
		let dynOff = 0;
		let dynSize = 0;
		for (let i = 0; i < phnum; i++) {
			const o = phoff + i * phentsize;
			const type = this.u32(o);
			if (type === PT_LOAD) this.segments.push({
				flags: this.u32(o + 4),
				offset: this.u64(o + 8),
				vaddr: this.u64(o + 16),
				filesz: this.u64(o + 32),
				memsz: this.u64(o + 40)
			});
			else if (type === PT_DYNAMIC) {
				dynOff = this.u64(o + 8);
				dynSize = this.u64(o + 32);
			}
		}
		if (this.segments.length === 0) throw new Error(`${this.path}: 没有 PT_LOAD`);
		const tags = /* @__PURE__ */ new Map();
		for (let o = dynOff; o < dynOff + dynSize; o += 16) {
			const tag = this.i64(o);
			if (tag === DT_NULL) break;
			if (!tags.has(tag)) tags.set(tag, this.u64(o + 8));
		}
		const strtabVa = tags.get(DT_STRTAB);
		const symtabVa = tags.get(DT_SYMTAB);
		if (strtabVa === void 0 || symtabVa === void 0) throw new Error(`${this.path}: 缺少 DT_STRTAB/DT_SYMTAB`);
		const strtab = this.vaToOff(strtabVa);
		const symtab = this.vaToOff(symtabVa);
		const symName = (off) => this.cstr(strtab + off);
		const so = tags.get(DT_SONAME);
		if (so !== void 0) this.soname = symName(so);
		for (const [tag, val] of tags) if (tag === DT_NEEDED) this.needed.push(symName(val));
		let nsym = 0;
		const hashVa = tags.get(DT_HASH);
		if (hashVa !== void 0) nsym = this.u32(this.vaToOff(hashVa) + 4);
		if (nsym === 0) nsym = Math.floor((strtab - symtab) / 24);
		if (nsym <= 0) throw new Error(`${this.path}: 无法确定 dynsym 数量`);
		for (let i = 0; i < nsym; i++) {
			const o = symtab + i * 24;
			const name = symName(this.u32(o));
			const info = d[o + 4];
			const shndx = this.u16(o + 6);
			const value = this.u64(o + 8);
			const sym = {
				name,
				value,
				size: this.u64(o + 16),
				bind: info >> 4,
				type: info & 15,
				shndx
			};
			this.symbols.push(sym);
			if (shndx !== 0 && value !== 0 && (sym.bind === 1 || sym.bind === 2) && name !== "") {
				if (!this.exports.has(name)) this.exports.set(name, value);
			}
		}
		const relaVa = tags.get(DT_RELA);
		const relaSz = tags.get(DT_RELASZ) ?? 0;
		const jmpVa = tags.get(DT_JMPREL);
		const jmpSz = tags.get(DT_PLTRELSZ) ?? 0;
		if (tags.get(DT_PLTREL) !== void 0 && tags.get(DT_PLTREL) !== 7) throw new Error(`${this.path}: 只支持 RELA 形式的 PLT 重定位`);
		const scan = (va, size) => {
			if (va === void 0 || size === 0) return;
			const base = this.vaToOff(va);
			for (let o = base; o < base + size; o += 24) {
				const offset = this.u64(o);
				const info = BigInt(this.u64(o + 8));
				const type = Number(info & 4294967295n);
				const symIdx = Number(info >> 32n);
				const sym = symIdx !== 0 ? this.symbols[symIdx]?.name ?? "" : "";
				this.relocs.push({
					offset,
					type,
					sym,
					addend: this.i64(o + 16)
				});
			}
		};
		scan(relaVa ?? 0, relaSz);
		scan(jmpVa ?? 0, jmpSz);
		this.initArrayVa = tags.get(DT_INIT_ARRAY) ?? 0;
		this.initArraySize = tags.get(DT_INIT_ARRAYSZ) ?? 0;
		this.finiArrayVa = tags.get(DT_FINI_ARRAY) ?? 0;
		this.finiArraySize = tags.get(DT_FINI_ARRAYSZ) ?? 0;
		let end = 0;
		for (const s of this.segments) end = Math.max(end, s.vaddr + s.memsz);
		this.extent = end + 65535 & -65536;
	}
};
/** 把镜像按 64 KiB 粒度映射到 base 并写入文件内容（bss 保持 0） */
function mapImage(mem, img, base) {
	for (const s of img.segments) {
		const lo = base + s.vaddr;
		const hi = base + s.vaddr + s.memsz;
		mem.map(lo & -65536, (hi + 65535 & -65536) - (lo & -65536));
		if (s.filesz > 0) mem.load(lo, img.data.subarray(s.offset, s.offset + s.filesz));
	}
}
/** 读 .init_array（必须在 applyRelocs 之后），返回绝对地址列表 */
function readInitArray(mem, img, base) {
	const out = [];
	for (let i = 0; i < img.initArraySize; i += 8) out.push(Number(mem.read(base + img.initArrayVa + i, 8)));
	return out;
}
/**
* 应用重定位（mapImage 之后调用）。resolve(name) 返回符号绝对地址，找不到返回 0。
* 未解析的 GLOB_DAT/JUMP_SLOT 记入 unresolved（槽位写 0）。
*/
function applyRelocs(mem, img, base, resolve) {
	const stats = {
		applied: 0,
		unresolved: /* @__PURE__ */ new Map()
	};
	for (const r of img.relocs) {
		const at = base + r.offset;
		switch (r.type) {
			case R_AARCH64_RELATIVE:
				mem.write(at, 8, BigInt(base + r.addend));
				stats.applied += 1;
				break;
			case 257:
			case R_AARCH64_GLOB_DAT:
			case R_AARCH64_JUMP_SLOT: {
				const addr = resolve(r.sym);
				if (addr === 0) {
					stats.unresolved.set(r.sym, (stats.unresolved.get(r.sym) ?? 0) + 1);
					mem.write(at, 8, 0n);
				} else {
					mem.write(at, 8, BigInt(r.type === 257 ? addr + r.addend : addr));
					stats.applied += 1;
				}
				break;
			}
			default: throw new Error(`${img.path}: 未支持的重定位类型 ${r.type} (sym=${r.sym})`);
		}
	}
	return stats;
}
//#endregion
//#region src/app/so/jit.ts
/**
* 块级 JIT：把一个基本块（顺序执行到控制流指令为止）翻译成一个 JS 函数。
*
* 生成的函数直接读写 cpu.xlo/xhi/vi，省掉逐条 fetch/classify/dispatch 的开销；
* 语义与 cpu.execFast 一一对应（同一份位域解码、同一套 lo/hi 运算顺序）。
*/
/** 单块最大指令数（太大不利于 V8 优化） */
const MAX_BLOCK = 80;
var Jit = class Jit {
	cpu;
	mem;
	stopPc;
	hooks;
	skip;
	/** pc 快查表：值 = list 下标 + 1，0 表示未编译 */
	idx;
	/** idx 指向的块 */
	list = [];
	/** 快查表覆盖的代码区间 [codeLo, codeHi) */
	codeLo;
	codeHi;
	/** 每个 64KiB 页是否有 hook（1 = 有） */
	hookPages;
	/** 代码区间外的块（正常不会用到） */
	slowBlocks = /* @__PURE__ */ new Map();
	L = [];
	u = 0;
	constructor(cpu, mem, stopPc, hooks, skip, codeLo = 0, codeHi = 0) {
		this.cpu = cpu;
		this.mem = mem;
		this.stopPc = stopPc;
		this.hooks = hooks;
		this.skip = skip;
		const span = codeHi > codeLo ? codeHi - codeLo : 0;
		this.codeLo = codeLo;
		this.codeHi = codeLo + span;
		this.idx = new Int32Array(span >>> 2);
		this.hookPages = new Uint8Array((span >>> 16) + 1);
		for (const p of hooks.keys()) {
			const off = p - codeLo;
			if (off >= 0 && off < span) this.hookPages[off >>> 16] = 1;
		}
	}
	/** 编译从 startPc 开始的基本块（块尾一定是「设好 cpu.pc 后 return」） */
	compile(startPc) {
		this.L = [];
		this.u = 0;
		this.e("let rlo=0,rhi=0;");
		let addr = startPc;
		let n = 0;
		/** -1 = 需要补块尾；-2 = 已由指令自己设好 pc 并 return */
		let tail = -1;
		for (;;) {
			if (addr === this.stopPc || n > 0 && this.hooks.has(addr)) break;
			const w = this.mem.fetch(addr);
			const cont = this.emitInstr(addr, w, classify(w));
			n += 1;
			addr += 4;
			if (!cont) {
				tail = -2;
				break;
			}
			if (n >= MAX_BLOCK) break;
		}
		if (tail === -1) this.e(`cpu.pc=${addr};`);
		const body = this.L.join("");
		let head = "const XLO=cpu.xlo,XHI=cpu.xhi";
		if (body.includes("VI[")) head += ",VI=cpu.vi";
		if (body.includes("DV[")) head += ",MEM=cpu.mem,DV=MEM.dv";
		else if (body.includes("MEM.")) head += ",MEM=cpu.mem";
		if (body.includes("T1[")) head += ",T1=cpu.t1";
		const src = `${head};${body}`;
		const b = {
			f: new Function("cpu", src),
			n
		};
		if (Jit.STAT) {
			b.c = 0;
			b.src = src;
		}
		const k = startPc - this.codeLo;
		if (k >= 0 && k < this.codeHi - this.codeLo) {
			this.idx[k >>> 2] = this.list.length + 1;
			this.list.push(b);
		} else this.slowBlocks.set(startPc, b);
		return b;
	}
	e(s) {
		this.L.push(s);
	}
	/** 读寄存器（x31 = xzr） */
	rl(r) {
		return r === 31 ? "0" : `XLO[${r}]`;
	}
	rh(r) {
		return r === 31 ? "0" : `XHI[${r}]`;
	}
	/** 写 64 位（x31 = xzr 丢弃） */
	wr64(rd, lo, hi) {
		if (rd === 31) return;
		this.e(`XLO[${rd}]=(${lo})|0;XHI[${rd}]=(${hi})|0;`);
	}
	/** 写 32 位（高位清零） */
	wr32(rd, v) {
		if (rd === 31) return;
		this.e(`XLO[${rd}]=(${v})|0;XHI[${rd}]=0;`);
	}
	/**
	* ADD/SUB 类写回：不置标志位时 rd=31 是 SP（必须写）；
	* 置标志位时（CMP/CMN 等）rd=31 是 XZR（丢弃）。
	*/
	wrAddsub(rd, sf, setF) {
		if (setF) {
			if (sf === 0) this.wr32(rd, "rlo");
			else this.wr64(rd, "rlo", "rhi");
			return;
		}
		if (sf === 0) this.e(`XLO[${rd}]=rlo|0;XHI[${rd}]=0;`);
		else this.e(`XLO[${rd}]=rlo|0;XHI[${rd}]=rhi|0;`);
	}
	/** 对 rlo/rhi 做 LSL/LSR/ASR/ROR（type 0/1/2/3），amount 为立即数 */
	emitShift(sf, type, amount) {
		const n = sf === 1 ? amount & 63 : amount & 31;
		if (sf === 1) {
			if (n === 0) return;
			if (type === 0) {
				if (n < 32) this.e(`rhi=(rhi<<${n})|(rlo>>>(32-${n}));rlo=rlo<<${n};`);
				else if (n === 32) this.e("rhi=rlo;rlo=0;");
				else this.e(`rhi=rlo<<${n - 32};rlo=0;`);
			} else if (type === 1) {
				if (n < 32) this.e(`rlo=(rlo>>>${n})|(rhi<<${32 - n});rhi=rhi>>>${n};`);
				else if (n === 32) this.e("rlo=rhi;rhi=0;");
				else this.e(`rlo=rhi>>>${n - 32};rhi=0;`);
			} else if (type === 2) {
				if (n < 32) this.e(`rlo=(rlo>>>${n})|(rhi<<${32 - n});rhi=rhi>>${n};`);
				else if (n === 32) this.e("rlo=rhi;rhi=rhi>>31;");
				else this.e(`rlo=rhi>>${n - 32};rhi=rhi>>31;`);
			} else if (n < 32) {
				const q = `q${this.u++}`;
				this.e(`let ${q}=rlo;rlo=(rlo>>>${n})|(rhi<<${32 - n});rhi=(rhi>>>${n})|(${q}<<${32 - n});`);
			} else if (n === 32) {
				const q = `q${this.u++}`;
				this.e(`let ${q}=rlo;rlo=rhi;rhi=${q};`);
			} else {
				const q = `q${this.u++}`;
				const m = n - 32;
				this.e(`let ${q}=rlo;rlo=(rhi>>>${m})|(rlo<<${32 - m});rhi=(${q}>>>${m})|(rhi<<${32 - m});`);
			}
			return;
		}
		if (type === 0) this.e(`rlo=rlo<<${n};rhi=0;`);
		else if (type === 1) this.e(`rlo=rlo>>>${n};rhi=0;`);
		else if (type === 2) this.e(`rlo=rlo>>${n};rhi=0;`);
		else if (n === 0) this.e("rhi=0;");
		else this.e(`rlo=(rlo>>>${n})|(rlo<<${32 - n});rhi=0;`);
	}
	/** 对 rlo/rhi 做 UXTB..SXTX（opt 0..7）再 LSL #shift */
	emitExtend(opt, shift, sf) {
		if (opt === 0) this.e("rlo=rlo&255;rhi=0;");
		else if (opt === 1) this.e("rlo=rlo&65535;rhi=0;");
		else if (opt === 2) this.e("rhi=0;");
		else if (opt === 4) this.e("rlo=(rlo<<24)>>24;rhi=rlo>>31;");
		else if (opt === 5) this.e("rlo=(rlo<<16)>>16;rhi=rlo>>31;");
		else if (opt === 6) this.e("rhi=rlo>>31;");
		const n = sf === 1 ? shift & 63 : shift & 31;
		if (n === 0) return;
		if (sf === 1) {
			if (n < 32) this.e(`rhi=(rhi<<${n})|(rlo>>>(32-${n}));rlo=rlo<<${n};`);
			else if (n === 32) this.e("rhi=rlo;rlo=0;");
			else this.e(`rhi=rlo<<${n - 32};rlo=0;`);
		} else this.e(`rlo=rlo<<${n};rhi=0;`);
	}
	/** rlo/rhi = rlo/rhi ± b（b 为表达式），setF 时写 cpu.nzcv */
	emitAddsub(sf, sub, setF, bLo, bHi) {
		const u = this.u++;
		if (sf === 1) {
			if (sub) {
				this.e(`let a${u}=rlo,a${u}h=rhi,d${u}=(a${u}>>>0)-(${bLo}>>>0),h${u}=(a${u}h>>>0)-(${bHi}>>>0)-(d${u}<0?1:0);rlo=d${u}|0;rhi=h${u}|0;`);
				if (setF) this.e(`cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2)|(h${u}<0?0:2)|((((a${u}h^(${bHi}))&(a${u}h^rhi))>>>31)&1);`);
			} else {
				this.e(`let a${u}=rlo,a${u}h=rhi,s${u}=(a${u}>>>0)+(${bLo}>>>0),h${u}=(a${u}h>>>0)+(${bHi}>>>0)+(s${u}>4294967295?1:0);rlo=s${u}|0;rhi=h${u}|0;`);
				if (setF) this.e(`cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2)|(h${u}>4294967295?2:0)|(((~((a${u}h)^(${bHi}))&((a${u}h)^rhi))>>>31)&1);`);
			}
			return;
		}
		if (sub) {
			this.e(`let a${u}=rlo,d${u}=(a${u}>>>0)-(${bLo}>>>0);rlo=d${u}|0;rhi=0;`);
			if (setF) this.e(`cpu.nzcv=((rlo>>>31)<<3)|((rlo===0?1:0)<<2)|(d${u}<0?0:2)|((((a${u}^(${bLo}))&(a${u}^rlo))>>>31)&1);`);
		} else {
			this.e(`let a${u}=rlo,s${u}=(a${u}>>>0)+(${bLo}>>>0);rlo=s${u}|0;rhi=0;`);
			if (setF) this.e(`cpu.nzcv=((rlo>>>31)<<3)|((rlo===0?1:0)<<2)|(s${u}>4294967295?2:0)|(((~((a${u})^(${bLo}))&((a${u})^rlo))>>>31)&1);`);
		}
	}
	/** rlo/rhi = 从 rlo/rhi 中按位域取 width 位（offset/width 为立即数） */
	emitExtract(offset, width) {
		if (offset === 0) {} else if (offset < 32) this.e(`rlo=(rlo>>>${offset})|(rhi<<${32 - offset});rhi=rhi>>>${offset};`);
		else if (offset === 32) this.e("rlo=rhi;rhi=0;");
		else this.e(`rlo=rhi>>>${offset - 32};rhi=0;`);
		if (width < 32) this.e(`rlo=rlo&${(1 << width) - 1};rhi=0;`);
		else if (width === 32) this.e("rhi=0;");
		else if (width < 64) this.e(`rhi=rhi&${(1 << width - 32) - 1};`);
	}
	/** num(r)：含 sp 的 64 位地址表达式（高 32 位为 0 时跳过浮点乘法） */
	numExpr(r) {
		return `(XHI[${r}]===0?XLO[${r}]>>>0:XHI[${r}]*4294967296+(XLO[${r}]>>>0))`;
	}
	/** 取页（顺带保证已分配），返回 [地址变量, DataView 变量] */
	pageOf(addrExpr) {
		const u = this.u++;
		this.e(`let A${u}=${addrExpr},P${u}=DV[A${u}>>>16];if(P${u}===undefined)P${u}=MEM.mkdv(A${u});`);
		return [`A${u}`, `P${u}`];
	}
	/** 读 bytes ∈ {1,2,4,8} 字节，返回 [lo, hi] 变量名 */
	emitLoad(bytes, A, P) {
		const u = this.u++;
		const o = `o${u}`;
		if (bytes === 8) {
			this.e(`let ${o}=${A}&65535,l${u}=0,h${u}=0;if(${o}>65528){l${u}=MEM.ld64(${A},T1);h${u}=T1[0];}else{l${u}=${P}.getUint32(${o},true)|0;h${u}=${P}.getUint32(${o}+4,true)|0;}`);
			return [`l${u}`, `h${u}`];
		}
		if (bytes === 4) this.e(`let ${o}=${A}&65535,v${u}=${o}>65532?MEM.ld32(${A}):${P}.getUint32(${o},true)|0;`);
		else if (bytes === 2) this.e(`let ${o}=${A}&65535,v${u}=${o}>65534?MEM.ld16(${A}):${P}.getUint16(${o},true)|0;`);
		else this.e(`let v${u}=${P}.getUint8(${A}&65535);`);
		return [`v${u}`, "0"];
	}
	/** 写 bytes ∈ {1,2,4,8} 字节 */
	emitStore(bytes, A, P, lo, hi) {
		const u = this.u++;
		const o = `o${u}`;
		if (bytes === 8) {
			this.e(`let ${o}=${A}&65535,s${u}=${lo},t${u}=${hi};if(${o}>65528)MEM.st64(${A},s${u},t${u});else{${P}.setUint32(${o},s${u},true);${P}.setUint32(${o}+4,t${u},true);}`);
			return;
		}
		if (bytes === 4) this.e(`let ${o}=${A}&65535,v${u}=${lo};if(${o}>65532)MEM.st32(${A},v${u});else ${P}.setUint32(${o},v${u},true);`);
		else if (bytes === 2) this.e(`let ${o}=${A}&65535,v${u}=${lo};if(${o}>65534)MEM.st16(${A},v${u});else ${P}.setUint16(${o},v${u},true);`);
		else this.e(`MEM.st8(${A},${lo});`);
	}
	emitLoadAt(bytes, addrExpr) {
		const [A, P] = this.pageOf(addrExpr);
		return this.emitLoad(bytes, A, P);
	}
	emitStoreAt(bytes, addrExpr, lo, hi) {
		const [A, P] = this.pageOf(addrExpr);
		this.emitStore(bytes, A, P, lo, hi);
	}
	/** 单寄存器访存（与 cpu.ldstOneN 等价） */
	emitLdstOne(w, addrExpr) {
		const size = w >>> 30;
		const V = w >>> 26 & 1;
		const opc = w >>> 22 & 3;
		const rt = w & 31;
		if (V === 1) {
			const k = rt * 4;
			if (size === 0 && opc >= 2) {
				if (opc === 2) {
					this.emitStoreAt(8, addrExpr, `VI[${k}]`, `VI[${k + 1}]`);
					this.emitStoreAt(8, `(${addrExpr}+8)`, `VI[${k + 2}]`, `VI[${k + 3}]`);
				} else {
					const [l0, h0] = this.emitLoadAt(8, addrExpr);
					const [l1, h1] = this.emitLoadAt(8, `(${addrExpr}+8)`);
					this.e(`VI[${k}]=${l0};VI[${k + 1}]=${h0};VI[${k + 2}]=${l1};VI[${k + 3}]=${h1};`);
				}
				return;
			}
			const bytes = 1 << size;
			if (opc === 0) {
				this.emitStoreAt(bytes, addrExpr, `VI[${k}]`, `VI[${k + 1}]`);
				return;
			}
			if (opc !== 1) return;
			const [l, h] = this.emitLoadAt(bytes, addrExpr);
			this.e(`VI[${k}]=${l};VI[${k + 1}]=${h};VI[${k + 2}]=0;VI[${k + 3}]=0;`);
			return;
		}
		if (opc === 0) {
			this.emitStoreAt(size === 3 ? 8 : 1 << size, addrExpr, this.rl(rt), this.rh(rt));
			return;
		}
		if (opc === 1) {
			const [l, h] = this.emitLoadAt(size === 3 ? 8 : 1 << size, addrExpr);
			if (rt !== 31) this.e(`XLO[${rt}]=${l};XHI[${rt}]=${h};`);
			return;
		}
		if (size === 3) return;
		const [l] = this.emitLoadAt(1 << size, addrExpr);
		if (rt === 31) return;
		if (size === 2) this.e(`XLO[${rt}]=${l};XHI[${rt}]=${l}>>31;`);
		else if (size === 1) this.e(`XLO[${rt}]=(${l}<<16)>>16;XHI[${rt}]=0;`);
		else this.e(`XLO[${rt}]=(${l}<<24)>>24;XHI[${rt}]=0;`);
	}
	/** 热类：整数运算与访存 */
	emitInstr(addr, w, c) {
		if (this.skip !== void 0 && this.skip.has(c)) return this.emitFallback(addr, w, c);
		switch (c) {
			case 14: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const shift = (w >>> 21 & 3) * 16;
				const imm = w >>> 5 & 65535;
				const rd = w & 31;
				if (rd === 31) return true;
				if (opc === 2) {
					if (shift < 32) this.e(`XLO[${rd}]=${imm}<<${shift};XHI[${rd}]=0;`);
					else this.e(`XLO[${rd}]=0;XHI[${rd}]=${imm}<<${shift - 32};`);
				} else if (opc === 0) {
					if (shift < 32) {
						const hi = shift === 0 ? "-1" : `~(${imm}>>>${32 - shift})`;
						this.e(`XLO[${rd}]=~(${imm}<<${shift});XHI[${rd}]=${sf === 1 ? hi : "0"};`);
					} else this.e(`XLO[${rd}]=-1;XHI[${rd}]=~(${imm}<<${shift - 32});`);
				} else if (opc === 3) {
					const s = shift < 32 ? shift : shift - 32;
					const m = `~(65535<<${s})`;
					if (shift < 32) this.e(`XLO[${rd}]=(XLO[${rd}]&${m})|(${imm}<<${shift});` + (sf === 1 ? "" : `XHI[${rd}]=0;`));
					else this.e(`XHI[${rd}]=(XHI[${rd}]&${m})|(${imm}<<${s});`);
				} else return this.emitFallback(addr, w, c);
				return true;
			}
			case 13: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const bm = this.cpu;
				bm.decodeBitMasksNum(w >>> 22 & 1, w >>> 10 & 63, w >>> 16 & 63, sf);
				const bmLo = bm.bmLo;
				const bmHi = bm.bmHi;
				this.e(`rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : "0"};`);
				if (opc === 3) {
					this.e(`rlo=rlo&${bmLo};rhi=rhi&${bmHi};cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2);`);
					this.wr32(rd, "rlo");
					return true;
				}
				if (opc === 0) this.e(`rlo=rlo&${bmLo};rhi=rhi&${bmHi};`);
				else if (opc === 1) this.e(`rlo=rlo|${bmLo};rhi=rhi|${bmHi};`);
				else this.e(`rlo=rlo^${bmLo};rhi=rhi^${bmHi};`);
				this.wr64(rd, "rlo", sf === 1 ? "rhi" : "0");
				return true;
			}
			case 37: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
				this.emitShift(sf, w >>> 22 & 3, w >>> 10 & 63);
				if ((w >>> 21 & 1) === 1) this.e(sf === 1 ? "rlo=~rlo;rhi=~rhi;" : "rlo=~rlo;");
				const u = this.u++;
				this.e(`let b${u}=rlo,c${u}=${sf === 1 ? "rhi" : "0"};rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : "0"};`);
				if (opc === 3) {
					this.e(`rlo=rlo&b${u};rhi=rhi&c${u};cpu.nzcv=((rhi>>>31)<<3)|(((rlo|rhi)===0?1:0)<<2);`);
					this.wr32(rd, "rlo");
					return true;
				}
				if (opc === 0) this.e(`rlo=rlo&b${u};rhi=rhi&c${u};`);
				else if (opc === 1) this.e(`rlo=rlo|b${u};rhi=rhi|c${u};`);
				else this.e(`rlo=rlo^b${u};rhi=rhi^c${u};`);
				this.wr64(rd, "rlo", sf === 1 ? "rhi" : "0");
				return true;
			}
			case 12: {
				const sf = w >>> 31;
				const setF = (w >>> 29 & 1) === 1;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const imm = (w >>> 10 & 4095) << ((w >>> 22 & 1) === 1 ? 12 : 0);
				this.e(`rlo=XLO[${rn}];rhi=XHI[${rn}];`);
				this.emitAddsub(sf, (w >>> 30 & 1) === 1, setF, String(imm), "0");
				this.wrAddsub(rd, sf, setF);
				return true;
			}
			case 35: {
				const sf = w >>> 31;
				const setF = (w >>> 29 & 1) === 1;
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
				this.emitShift(sf, w >>> 22 & 3, w >>> 10 & 63);
				const u = this.u++;
				this.e(`let b${u}=rlo,c${u}=${sf === 1 ? "rhi" : "0"};rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : "0"};`);
				this.emitAddsub(sf, (w >>> 30 & 1) === 1, setF, `b${u}`, `c${u}`);
				if (setF && sf === 0) this.wr32(rd, "rlo");
				else this.wr64(rd, "rlo", "rhi");
				return true;
			}
			case 36: {
				const sf = w >>> 31;
				const setF = (w >>> 29 & 1) === 1;
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
				this.emitExtend(w >>> 13 & 7, w >>> 10 & 7, sf);
				const u = this.u++;
				this.e(`let b${u}=rlo,c${u}=${sf === 1 ? "rhi" : "0"};rlo=XLO[${rn}];rhi=${sf === 1 ? `XHI[${rn}]` : "0"};`);
				this.emitAddsub(sf, (w >>> 30 & 1) === 1, setF, `b${u}`, `c${u}`);
				this.wrAddsub(rd, sf, setF);
				return true;
			}
			case 15: {
				const sf = w >>> 31;
				const opc = w >>> 29 & 3;
				const immr = w >>> 16 & 63;
				const imms = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const dsz = sf === 1 ? 64 : 32;
				const width = imms >= immr ? imms - immr + 1 : imms + 1;
				const lsb = imms >= immr ? 0 : dsz - immr;
				this.e(`rlo=${this.rl(rn)};rhi=${sf === 1 ? this.rh(rn) : "0"};`);
				this.emitExtract(imms >= immr ? immr : 0, width);
				if (opc === 0 && width < dsz) {
					if (width < 32) this.e(`if((rlo>>>${width - 1})&1){rlo=rlo|${~((1 << width) - 1)};rhi=-1;}`);
					else if (width === 32) this.e("if((rlo>>>31)&1)rhi=-1;");
					else this.e(`if((rhi>>>${width - 33})&1){rhi=rhi|${~((1 << width - 32) - 1)};}`);
				}
				this.emitShift(sf, 0, lsb);
				if (opc === 0 || opc === 2) {
					this.wr64(rd, "rlo", "rhi");
					return true;
				}
				let mLo = 0;
				let mHi = 0;
				if (lsb < 32) {
					const loBits = Math.min(width, 32 - lsb);
					mLo = loBits >= 32 ? -1 : (1 << loBits) - 1 << lsb;
					if (width > loBits) {
						const hiBits = width - loBits;
						mHi = hiBits >= 32 ? -1 : (1 << hiBits) - 1;
					}
				} else {
					const hiBits = Math.min(width, 64 - lsb);
					mHi = hiBits >= 32 ? -1 : (1 << hiBits) - 1 << lsb - 32;
				}
				if (rd !== 31) this.e(`XLO[${rd}]=rlo|(XLO[${rd}]&${~mLo});XHI[${rd}]=${sf === 1 ? `rhi|(XHI[${rd}]&${~mHi})` : "0"};`);
				return true;
			}
			case 16: {
				const sf = w >>> 31;
				const rm = w >>> 16 & 31;
				const lsb = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const u = this.u++;
				this.e(`let b${u}=${this.rl(rm)},c${u}=${this.rh(rm)},a${u}=${this.rl(rn)},d${u}=${this.rh(rn)};`);
				if (sf === 0) {
					const n = lsb & 31;
					this.e(n === 0 ? `rlo=b${u};rhi=0;` : `rlo=(b${u}>>>${n})|(a${u}<<${32 - n});rhi=0;`);
				} else if (lsb === 0) this.e(`rlo=b${u};rhi=c${u};`);
				else if (lsb < 32) this.e(`rlo=(b${u}>>>${lsb})|(c${u}<<${32 - lsb});rhi=(c${u}>>>${lsb})|(a${u}<<${32 - lsb});`);
				else if (lsb === 32) this.e(`rlo=c${u};rhi=a${u};`);
				else {
					const m = lsb - 32;
					this.e(`rlo=(c${u}>>>${m})|(a${u}<<${32 - m});rhi=(a${u}>>>${m})|(d${u}<<${32 - m});`);
				}
				this.wr64(rd, "rlo", "rhi");
				return true;
			}
			case 39: {
				const sf = w >>> 31;
				const op = w >>> 30 & 1;
				const rm = w >>> 16 & 31;
				const op2 = w >>> 10 & 3;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				const t = `c${this.u++}`;
				let els = `rlo=${this.rl(rm)};rhi=${this.rh(rm)};`;
				if (op === 0) {
					if (op2 === 1) els += sf === 1 ? `let ${t}=(rlo>>>0)+1;rlo=${t}|0;if(${t}>4294967295)rhi=(rhi+1)|0;` : `rlo=(rlo+1)|0;`;
				} else if (op2 === 0) els += sf === 1 ? "rlo=~rlo;rhi=~rhi;" : "rlo=~rlo;";
				else if (sf === 1) els += `let ${t}=(rlo>>>0)===0?1:0;rlo=(~rlo+1)|0;rhi=(~rhi+${t})|0;`;
				else els += "rlo=(~rlo+1)|0;";
				this.e(`if(${this.condExpr(w >>> 12 & 15)}){rlo=${this.rl(rn)};rhi=${this.rh(rn)};}else{${els}}`);
				this.e(`XLO[${rd}]=rlo|0;XHI[${rd}]=${sf === 1 ? "rhi" : "0"}|0;`);
				return true;
			}
			case 28: {
				const opc = w >>> 30;
				const V = w >>> 26 & 1;
				const L = w >>> 22 & 1;
				const idx = w >>> 23 & 3;
				const rn = w >>> 5 & 31;
				const rt = w & 31;
				const rt2 = w >>> 10 & 31;
				const bytes = V === 1 ? 4 << opc : opc === 2 ? 8 : 4;
				const imm = ((w >>> 15 & 127) << 25 >> 25) * bytes;
				const p = `p${this.u++}`;
				this.e(`let ${p}=${this.numExpr(rn)}${idx === 1 ? "" : `+${imm}`};`);
				if (L === 1) {
					if (V === 1) {
						const k = rt * 4;
						const k2 = rt2 * 4;
						if (bytes === 16) {
							const [l0, h0] = this.emitLoadAt(8, p);
							const [l1, h1] = this.emitLoadAt(8, `(${p}+8)`);
							const [l2, h2] = this.emitLoadAt(8, `(${p}+16)`);
							const [l3, h3] = this.emitLoadAt(8, `(${p}+24)`);
							this.e(`VI[${k}]=${l0};VI[${k + 1}]=${h0};VI[${k + 2}]=${l1};VI[${k + 3}]=${h1};VI[${k2}]=${l2};VI[${k2 + 1}]=${h2};VI[${k2 + 2}]=${l3};VI[${k2 + 3}]=${h3};`);
						} else if (bytes === 8) {
							const [l0, h0] = this.emitLoadAt(8, p);
							const [l1, h1] = this.emitLoadAt(8, `(${p}+8)`);
							this.e(`VI[${k}]=${l0};VI[${k + 1}]=${h0};VI[${k + 2}]=0;VI[${k + 3}]=0;VI[${k2}]=${l1};VI[${k2 + 1}]=${h1};VI[${k2 + 2}]=0;VI[${k2 + 3}]=0;`);
						} else {
							const [l0] = this.emitLoadAt(4, p);
							const [l1] = this.emitLoadAt(4, `(${p}+4)`);
							this.e(`VI[${k}]=${l0};VI[${k + 1}]=0;VI[${k + 2}]=0;VI[${k + 3}]=0;VI[${k2}]=${l1};VI[${k2 + 1}]=0;VI[${k2 + 2}]=0;VI[${k2 + 3}]=0;`);
						}
					} else if (bytes === 8) {
						const [l0, h0] = this.emitLoadAt(8, p);
						const [l1, h1] = this.emitLoadAt(8, `(${p}+8)`);
						if (rt !== 31) this.e(`XLO[${rt}]=${l0};XHI[${rt}]=${h0};`);
						if (rt2 !== 31) this.e(`XLO[${rt2}]=${l1};XHI[${rt2}]=${h1};`);
					} else {
						const [l0] = this.emitLoadAt(4, p);
						const [l1] = this.emitLoadAt(4, `(${p}+4)`);
						const sx = opc === 1;
						if (rt !== 31) this.e(`XLO[${rt}]=${l0};XHI[${rt}]=${sx ? `${l0}>>31` : "0"};`);
						if (rt2 !== 31) this.e(`XLO[${rt2}]=${l1};XHI[${rt2}]=${sx ? `${l1}>>31` : "0"};`);
					}
				} else if (V === 1) {
					const k = rt * 4;
					const k2 = rt2 * 4;
					if (bytes === 16) {
						this.emitStoreAt(8, p, `VI[${k}]`, `VI[${k + 1}]`);
						this.emitStoreAt(8, `(${p}+8)`, `VI[${k + 2}]`, `VI[${k + 3}]`);
						this.emitStoreAt(8, `(${p}+16)`, `VI[${k2}]`, `VI[${k2 + 1}]`);
						this.emitStoreAt(8, `(${p}+24)`, `VI[${k2 + 2}]`, `VI[${k2 + 3}]`);
					} else if (bytes === 8) {
						this.emitStoreAt(8, p, `VI[${k}]`, `VI[${k + 1}]`);
						this.emitStoreAt(8, `(${p}+8)`, `VI[${k2}]`, `VI[${k2 + 1}]`);
					} else {
						this.emitStoreAt(4, p, `VI[${k}]`, "0");
						this.emitStoreAt(4, `(${p}+4)`, `VI[${k2}]`, "0");
					}
				} else if (bytes === 8) {
					this.emitStoreAt(8, p, this.rl(rt), this.rh(rt));
					this.emitStoreAt(8, `(${p}+8)`, this.rl(rt2), this.rh(rt2));
				} else {
					this.emitStoreAt(4, p, this.rl(rt), "0");
					this.emitStoreAt(4, `(${p}+4)`, this.rl(rt2), "0");
				}
				if (idx === 1) this.e(`XLO[${rn}]=(${p}+${imm})|0;XHI[${rn}]=Math.floor((${p}+${imm})/4294967296)|0;`);
				else if (idx === 3) this.e(`XLO[${rn}]=${p}|0;XHI[${rn}]=Math.floor(${p}/4294967296)|0;`);
				return true;
			}
			case 42: {
				const sf = w >>> 31;
				const rm = w >>> 16 & 31;
				const opcode = w >>> 10 & 63;
				const rn = w >>> 5 & 31;
				const rd = w & 31;
				if (rd === 31) return true;
				const u = this.u++;
				const n = `n${u}`;
				if (opcode === 2 || opcode === 3) {
					const a = this.rl(rn);
					const b = this.rl(rm);
					if (sf === 0) {
						const q = `q${u}`;
						const div = opcode === 2 ? `((${a}>>>0)/(${q}>>>0))|0` : `((${a}|0)/${q})|0`;
						this.e(`let ${q}=${b}|0;XHI[${rd}]=0;XLO[${rd}]=${q}===0?0:(${div});`);
					} else {
						const A = `A${u}`;
						const B = `B${u}`;
						const R = `R${u}`;
						this.e(`let ${A}=(BigInt(${this.rh(rn)}>>>0)<<32n)|BigInt(${a}>>>0),${B}=(BigInt(${this.rh(rm)}>>>0)<<32n)|BigInt(${b}>>>0);`);
						if (opcode === 2) this.e(`let ${R}=${B}===0n?0n:(${A}/${B});`);
						else this.e(`let ${R}=${B}===0n?0n:BigInt.asUintN(64,BigInt.asIntN(64,${A})/BigInt.asIntN(64,${B}));`);
						this.e(`XLO[${rd}]=Number(${R}&0xffffffffn)|0;XHI[${rd}]=Number(${R}>>32n)|0;`);
					}
					return true;
				}
				if (opcode < 8 || opcode > 11) return this.emitFallback(addr, w, c);
				const type = opcode - 8;
				const a = this.rl(rn);
				const ah = this.rh(rn);
				if (sf === 0) {
					this.e(`let ${n}=${this.rl(rm)}&31;`);
					if (type === 0) this.e(`XLO[${rd}]=(${a}<<${n})|0;XHI[${rd}]=0;`);
					else if (type === 1) this.e(`XLO[${rd}]=(${a}>>>${n})|0;XHI[${rd}]=0;`);
					else if (type === 2) this.e(`XLO[${rd}]=(${a}>>${n})|0;XHI[${rd}]=0;`);
					else this.e(`XLO[${rd}]=((${a}>>>${n})|(${a}<<(32-${n})))|0;XHI[${rd}]=0;`);
					return true;
				}
				this.e(`let ${n}=${this.rl(rm)}&63;`);
				const lo = `l${u}`;
				const hi = `h${u}`;
				if (type === 0) this.e(`let ${lo}=${a},${hi}=${ah};if(${n}===0){}else if(${n}<32){${hi}=(${hi}<<${n})|(${lo}>>>(32-${n}));${lo}=${lo}<<${n};}else if(${n}===32){${hi}=${lo};${lo}=0;}else{${hi}=${lo}<<(${n}-32);${lo}=0;}`);
				else if (type === 1) this.e(`let ${lo}=${a},${hi}=${ah};if(${n}===0){}else if(${n}<32){${lo}=(${lo}>>>${n})|(${hi}<<(32-${n}));${hi}=${hi}>>>${n};}else if(${n}===32){${lo}=${hi};${hi}=0;}else{${lo}=${hi}>>>(${n}-32);${hi}=0;}`);
				else if (type === 2) this.e(`let ${lo}=${a},${hi}=${ah};if(${n}===0){}else if(${n}<32){${lo}=(${lo}>>>${n})|(${hi}<<(32-${n}));${hi}=${hi}>>${n};}else if(${n}===32){${lo}=${hi};${hi}=${hi}>>31;}else{${lo}=${hi}>>(${n}-32);${hi}=${hi}>>31;}`);
				else this.e(`let ${lo}=${a},${hi}=${ah};if(${n}===0){}else if(${n}<32){let t${u}=${lo};${lo}=(${lo}>>>${n})|(${hi}<<(32-${n}));${hi}=(${hi}>>>${n})|(t${u}<<(32-${n}));}else if(${n}===32){let t${u}=${lo};${lo}=${hi};${hi}=t${u};}else{let t${u}=${lo};${lo}=(${hi}>>>(${n}-32))|(${lo}<<(32-(${n}-32)));${hi}=(t${u}>>>(${n}-32))|(${hi}<<(32-(${n}-32)));}`);
				this.e(`XLO[${rd}]=${lo}|0;XHI[${rd}]=${hi}|0;`);
				return true;
			}
			case 11: {
				const off = ((w >> 5 & 524287) << 2 | w >>> 29 & 3) << 11 >> 11;
				const v = w >>> 31 === 1 ? (addr & -4096) + off * 4096 : addr + off;
				this.wr64(w & 31, String(v | 0), String(Math.floor(v / 4294967296) | 0));
				return true;
			}
			case 29: {
				const rn = w >>> 5 & 31;
				const bytes = this.ldstBytes(w);
				this.emitLdstOne(w, `(${this.numExpr(rn)}+${(w >>> 10 & 4095) * bytes})`);
				return true;
			}
			case 31: {
				const rn = w >>> 5 & 31;
				const off = (w >>> 12 & 511) << 23 >> 23;
				this.emitLdstOne(w, `(${this.numExpr(rn)}+${off})`);
				return true;
			}
			case 33: {
				const rn = w >>> 5 & 31;
				const off = (w >>> 12 & 511) << 23 >> 23;
				const u = this.u++;
				this.e(`let n${u}=${this.numExpr(rn)}+${off};XLO[${rn}]=n${u}|0;XHI[${rn}]=Math.floor(n${u}/4294967296)|0;`);
				this.emitLdstOne(w, `n${u}`);
				return true;
			}
			case 32: {
				const rn = w >>> 5 & 31;
				const off = (w >>> 12 & 511) << 23 >> 23;
				const u = this.u++;
				this.e(`let n${u}=${this.numExpr(rn)};`);
				this.emitLdstOne(w, `n${u}`);
				this.e(`XLO[${rn}]=(n${u}+${off})|0;XHI[${rn}]=Math.floor((n${u}+${off})/4294967296)|0;`);
				return true;
			}
			case 34: {
				const off = (w >>> 5 & 524287) << 13 >> 13;
				this.emitLdstOne(w, `(${addr + 4 + off * 4})`);
				return true;
			}
			case 30: {
				const size = w >>> 30;
				const rm = w >>> 16 & 31;
				const rn = w >>> 5 & 31;
				const bytes = this.ldstBytes(w);
				const shift = (w >>> 12 & 1) === 1 ? bytes === 16 ? 4 : size : 0;
				this.e(`rlo=${this.rl(rm)};rhi=${this.rh(rm)};`);
				this.emitExtend(w >>> 13 & 7, shift, 1);
				const u = this.u++;
				this.e(`let r${u}=rhi*4294967296+(rlo>>>0);`);
				this.emitLdstOne(w, `(${this.numExpr(rn)}+r${u})`);
				return true;
			}
			default: return this.emitOther(addr, w, c);
		}
	}
	/** ldstBytes：SIMD 128 位（V=1,size=0,opc>=2）按 16 字节算 */
	ldstBytes(w) {
		return (w >>> 26 & 1) === 1 && w >>> 30 === 0 && (w >>> 22 & 3) >= 2 ? 16 : 1 << (w >>> 30);
	}
	/** 条件码 → JS 布尔表达式（与 cpu.cond 等价，编译期展开） */
	condExpr(c) {
		if (c >= 14) return "true";
		const n = "((cpu.nzcv&8)!==0)";
		const z = "((cpu.nzcv&4)!==0)";
		const cy = "((cpu.nzcv&2)!==0)";
		const v = "((cpu.nzcv&1)!==0)";
		let r;
		switch (c >> 1) {
			case 0:
				r = z;
				break;
			case 1:
				r = cy;
				break;
			case 2:
				r = n;
				break;
			case 3:
				r = v;
				break;
			case 4:
				r = `(${cy}&&!${z})`;
				break;
			case 5:
				r = `(${n}===${v})`;
				break;
			case 6:
				r = `(${n}===${v}&&!${z})`;
				break;
			default: r = "true";
		}
		return (c & 1) !== 0 ? `(!${r})` : r;
	}
	/** SO_JITSTAT：记录每块执行次数与源码（调优用） */
	static STAT = !!process.env.SO_JITSTAT;
	/** 控制流类：块必须在此结束 */
	static CF = /* @__PURE__ */ new Set([
		2,
		3,
		20,
		17,
		18,
		19,
		21,
		22,
		23
	]);
	/** 回退：把这条指令交给解释器执行（非控制流类可继续块内后续指令） */
	emitFallback(addr, w, c) {
		this.e(`cpu.pc=${addr + 4};cpu.exec(${c},${w});`);
		if (Jit.CF.has(c)) {
			this.e("return;");
			return false;
		}
		return true;
	}
	/** 其余指令类：控制流 / 向量 / 空操作 */
	emitOther(addr, w, c) {
		switch (c) {
			case 20: {
				const off = (w & 67108863) << 6 >> 6;
				if (w >>> 31 === 1) this.wr64(30, String(addr + 4), "0");
				this.e(`cpu.pc=${addr + off * 4};return;`);
				return false;
			}
			case 17: {
				const off = (w >>> 5 & 524287) << 13 >> 13;
				this.e(`cpu.pc=${addr + 4};if(${this.condExpr(w & 15)})cpu.pc=${addr + off * 4};return;`);
				return false;
			}
			case 18: {
				const rt = w & 31;
				const sf = w >>> 31;
				const nz = w >>> 24 & 1;
				const off = (w >>> 5 & 524287) << 13 >> 13;
				const v = rt === 31 ? "0" : sf === 1 ? `(XLO[${rt}]|XHI[${rt}])` : `XLO[${rt}]`;
				const test = nz === 1 ? `(${v})!==0` : `(${v})===0`;
				this.e(`cpu.pc=${addr + 4};if(${test})cpu.pc=${addr + off * 4};return;`);
				return false;
			}
			case 19: {
				const bit = (w >>> 31 & 1) << 5 | w >>> 19 & 31;
				const rt = w & 31;
				const nz = w >>> 24 & 1;
				const off = (w >>> 5 & 16383) << 18 >> 18;
				const v = rt === 31 ? "0" : bit < 32 ? `((XLO[${rt}]>>>${bit})&1)` : `((XHI[${rt}]>>>${bit - 32})&1)`;
				this.e(`cpu.pc=${addr + 4};if((${v})===${nz})cpu.pc=${addr + off * 4};return;`);
				return false;
			}
			case 21:
				this.e(`cpu.pc=${this.numExpr(w >>> 5 & 31)};return;`);
				return false;
			case 22:
				this.e(`cpu.pc=${this.numExpr(w >>> 5 & 31)};`);
				this.wr64(30, String(addr + 4), "0");
				this.e("return;");
				return false;
			case 23:
				this.e(`cpu.pc=${this.numExpr(w >>> 5 & 31)};return;`);
				return false;
			case 76: {
				const Q = w >>> 30 & 1;
				const op = (w >>> 29 & 1) << 2 | w >>> 22 & 3;
				const k = (w & 31) * 4;
				const an = (w >>> 5 & 31) * 4;
				const am = (w >>> 16 & 31) * 4;
				for (let i = 0; i < 4; i++) {
					const a = `VI[${an + i}]`;
					const b = `VI[${am + i}]`;
					const d = `VI[${k + i}]`;
					let s;
					if (op === 0) s = `${a}&${b}`;
					else if (op === 1) s = `${a}&~${b}`;
					else if (op === 2) s = `${a}|${b}`;
					else if (op === 3) s = `${a}|~${b}`;
					else if (op === 4) s = `${a}^${b}`;
					else if (op === 5 || op === 6) s = `(${a}&${b})|(~${a}&${d})`;
					else s = `(${a}&${d})|(~${a}&${b})`;
					this.e(`${d}=${s};`);
				}
				if (Q !== 1) this.e(`VI[${k + 2}]=0;VI[${k + 3}]=0;`);
				return true;
			}
			case 77: {
				const Q = w >>> 30 & 1;
				const imm5 = w >>> 16 & 31;
				const low = imm5 & -imm5;
				const sz = 31 - Math.clz32(low);
				const esize = 8 << sz;
				const bit = (imm5 >> sz + 1) * esize;
				const k = (w >>> 5 & 31) * 4 + (bit >>> 5);
				const rd = w & 31;
				if (rd === 31) return true;
				if (esize === 64) {
					this.e(`XLO[${rd}]=VI[${k}];XHI[${rd}]=${Q === 1 ? `VI[${k + 1}]` : "0"};`);
					return true;
				}
				const sh = bit & 31;
				let v;
				if (sh === 0) v = `VI[${k}]`;
				else v = `(VI[${k}]>>>${sh})|(VI[${k + 1}]<<${32 - sh})`;
				if (esize === 32) this.e(`XLO[${rd}]=${v}|0;XHI[${rd}]=0;`);
				else if (esize === 16) this.e(`XLO[${rd}]=(${v})&65535;XHI[${rd}]=0;`);
				else this.e(`XLO[${rd}]=(${v})&255;XHI[${rd}]=0;`);
				return true;
			}
			case 81:
				this.e(`cpu.vzipN(${w},true);`);
				return true;
			case 82:
				this.e(`cpu.vzipN(${w},false);`);
				return true;
			case 83:
				this.e(`cpu.vextN(${w});`);
				return true;
			case 84:
				this.e(`cpu.vushlN(${w});`);
				return true;
			case 78:
				this.e(`cpu.vdupN(${w},false);`);
				return true;
			case 79:
				this.e(`cpu.vdupN(${w},true);`);
				return true;
			case 46: {
				const rd = w & 31;
				if (rd !== 31) this.e(`XLO[${rd}]=VI[${(w >>> 5 & 31) * 4}];XHI[${rd}]=0;`);
				return true;
			}
			case 1:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8: return true;
			default: return this.emitFallback(addr, w, c);
		}
	}
};
//#endregion
//#region src/app/so/alloc.ts
/** oracle dlmalloc 分配序列（name n addr），冷启动时按序回放地址 */
const ALLOC_REPLAY = `
malloc 4 40797610
calloc 2986 40ae5c00
malloc 24 407a4cc0
malloc 2987 40ae5000
malloc 4 40797660
malloc 4 40797610
malloc 40 40795df0
malloc 40 40795c40
malloc 40 40795c70
malloc 4 40797620
malloc 40 40795cd0
malloc 40 40795d30
malloc 17 407a4680
malloc 40 40af5120
malloc 40 40af50f0
malloc 40 40795d00
malloc 48 40795e50
malloc 4 40797188
malloc 24 407a4ce0
malloc 14 40798480
malloc 13 40798480
malloc 13 40798480
malloc 19 407a4dc0
malloc 2940 40ae5c00
malloc 8 40797640
malloc 4 407973f0
malloc 8 40797648
malloc 2 40797168
malloc 2 40797170
malloc 8 40797190
malloc 5 40797168
realloc 8 40797168
malloc 4 40797190
realloc 8 40797190
malloc 5 40797190
malloc 19 407a4ce0
malloc 4 407973f0
malloc 19 407a4dc0
malloc 16 40798480
malloc 160 40799d20
malloc 16 407984d0
malloc 48 40795e80
malloc 4 40797640
malloc 15 407984d0
malloc 8 40797168
malloc 9 40798500
malloc 4 40797648
malloc 40 40795e80
malloc 40 40795eb0
malloc 40 40af5030
malloc 48 40af5060
malloc 4 40797170
malloc 24 407a4ce0
malloc 8 40797410
malloc 4 40797600
malloc 16 407984f0
malloc 8 40797618
malloc 32 407a4e40
malloc 8 40797618
malloc 16 407984f0
malloc 7 40797410
malloc 24 407a4ce0
malloc 7 40797600
malloc 4 40797618
malloc 152 40799dc0
malloc 48 40af5090
malloc 24 407a4e40
malloc 8 40797628
malloc 4 40797630
malloc 16 40798520
malloc 8 40797650
malloc 32 407a4de0
malloc 64 4079e6c0
malloc 128 40796200
malloc 64 4079e6c0
malloc 8 40797628
malloc 24 407a4de0
malloc 8 40797650
malloc 4 40797668
malloc 64 4079ee40
malloc 16 40798520
malloc 8 40797650
malloc 32 407a42c0
malloc 128 40796200
malloc 256 407b7500
malloc 128 40796200
malloc 64 4079ee40
malloc 4 40797410
malloc 24 407a4ce0
malloc 8 40797410
malloc 4 40797600
malloc 16 40798520
malloc 8 40797618
malloc 32 407a4e40
malloc 64 4079ee40
malloc 128 40796200
malloc 64 4079ee40
malloc 24 407a4e40
malloc 8 40797410
malloc 4 40797618
malloc 64 4079e6c0
malloc 7 40797410
malloc 7 40797630
malloc 64 4079ee80
malloc 24 407a4de0
malloc 8 40797410
malloc 4 40797630
malloc 16 40798520
malloc 8 40797668
malloc 32 407a42c0
malloc 128 40796200
malloc 256 407b7500
malloc 128 40796200
malloc 4 40797600
malloc 12 40798520
malloc 24 407a4de0
malloc 8 40797600
malloc 4 40797630
malloc 64 4079ee40
malloc 48 40af5090
malloc 4 40797600
malloc 4 40797600
malloc 4 407973e0
malloc 24 407a4de0
malloc 1 40797648
malloc 4 40797170
malloc 32 407a4de0
malloc 40 40795e80
malloc 40 40795eb0
malloc 40 40af5030
malloc 4 40797648
malloc 48 40af5090
malloc 4 40797170
malloc 1 40797600
malloc 4 40797600
malloc 48 40af50c0
malloc 24 407a4ce0
malloc 1 40797630
malloc 4 40797618
malloc 1 40797630
malloc 1 40797630
malloc 1 40797630
malloc 1 40797630
malloc 1 40797630
malloc 2 40797630
malloc 40 40af5150
malloc 1 40797618
malloc 16 407984f0
malloc 64 4079ee40
malloc 48 40af5180
malloc 4 40797618
malloc 1 40797410
malloc 1 40797410
malloc 1 40797410
malloc 1 40797410
malloc 16 40798520
malloc 32 407a4ce0
malloc 40 40af51b0
malloc 40 40af51e0
malloc 40 40af5210
malloc 48 40af5240
malloc 4 40797410
malloc 48 40af5270
malloc 4 40797668
malloc 1 40797628
malloc 9 40798470
malloc 32 407a4de0
malloc 40 40795e80
malloc 40 40795eb0
malloc 40 40af5030
malloc 4 40797630
malloc 48 40af5150
malloc 4 40797648
malloc 1 40797170
malloc 24 407a4e40
malloc 1 40797170
malloc 4 40797628
malloc 1 40797170
malloc 1 40797170
malloc 1 40797170
malloc 1 40797170
malloc 1 40797170
malloc 2 40797170
malloc 40 40af5090
malloc 1 40797628
malloc 1 40797628
malloc 1 40797628
malloc 1 40797628
malloc 1 40797628
malloc 1 40797628
malloc 9 40798470
malloc 16 40798500
malloc 10 40798490
malloc 11 407984a0
malloc 19 407a4de0
malloc 17 407a4e40
malloc 24 407a42c0
malloc 17 407a4300
malloc 4 40797170
malloc 24 407a4700
malloc 17 407a4c20
malloc 4 40797630
malloc 10 407984b0
malloc 8 40797648
malloc 5 40797628
malloc 5 40797628
malloc 16 407984b0
malloc 5 40797628
malloc 5 40797628
malloc 32 407a4c60
malloc 5 40797628
malloc 24 407a4d00
malloc 8 40797628
malloc 4 40797648
malloc 32 407a4d60
malloc 24 407a4d80
malloc 8 40797628
malloc 4 40797650
malloc 64 4079e6c0
malloc 53 4079ee80
malloc 9 407984b0
malloc 53 4079e6c0
malloc 24 407a4e40
malloc 9 407984c0
malloc 24 407a42c0
malloc 53 4079ee80
malloc 16 407984e0
malloc 40 40795e80
malloc 10 407984b0
malloc 11 40798510
malloc 24 407a4300
malloc 10 40798530
malloc 24 407a4700
malloc 11 40798540
malloc 16 40798550
malloc 40 40795eb0
malloc 24 407a4c20
malloc 8 40797170
malloc 5 40797630
malloc 16 40798510
malloc 2 40797630
malloc 24 407a4c60
malloc 8 40797630
malloc 16 407984b0
malloc 40 40af5030
malloc 24 407a4d00
malloc 8 40797170
malloc 5 40797648
malloc 16 40798560
malloc 2 40797648
malloc 24 407a4d60
malloc 8 40797648
malloc 16 40798570
malloc 40 40af5090
malloc 5 40797170
malloc 8 40797650
malloc 16 40798580
malloc 8 40797628
malloc 32 407a4d80
malloc 64 4079e6c0
malloc 32 407a4d80
malloc 5 40797650
malloc 5 40797628
malloc 16 40798580
malloc 24 407a4da0
malloc 8 40797628
malloc 4 40797670
malloc 64 4079e6c0
malloc 33 40af5150
malloc 5 40797650
malloc 8 40797670
malloc 33 40af52a0
malloc 33 40af52d0
malloc 27 407a4da0
malloc 8 40797628
realloc 64 4079e6c0
malloc 33 40af5300
malloc 32 407a4da0
malloc 64 4079e6c0
malloc 64 4079ed80
malloc 49 4079eec0
malloc 24 407a4da0
malloc 49 4079ee00
malloc 4 40797650
malloc 49 4079eec0
malloc 9 40798580
malloc 49 4079ee00
malloc 24 407a4d80
malloc 9 40798590
malloc 24 407a4da0
malloc 49 4079ed80
malloc 16 407985a0
malloc 40 40af5150
malloc 8 40797170
malloc 8 40797650
malloc 8 40797670
malloc 33 40af52a0
malloc 53 4079ee00
malloc 21 407a4e00
malloc 16384 40b17000
malloc 33 40af52d0
malloc 1 40797650
malloc 8 40797170
malloc 1 40797650
malloc 32 407a4e20
malloc 4 40797650
malloc 24 407a4e60
malloc 8 40797628
malloc 48 40af52d0
malloc 4 40797678
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 33 40af5300
malloc 8 40797650
malloc 8 40797680
malloc 8 40797688
malloc 33 40af5300
malloc 48 40af5300
malloc 16 40798580
malloc 4096 4078c000
malloc 24 407a4e80
malloc 37 40af5330
malloc 4 40797690
malloc 24 407a4ea0
malloc 8 40797698
malloc 48 40af5360
malloc 4 407976a0
malloc 16 407985b0
malloc 8 407976a8
malloc 32 407a4ec0
malloc 37 40af5390
realloc 64 4079ee00
malloc 24 407a4ec0
malloc 8 407976a8
malloc 48 40af5390
malloc 4 407976b0
malloc 64 4079e6c0
malloc 16 407985b0
malloc 64 4079ee00
malloc 4 407976b0
malloc 64 4079ee00
malloc 64 4079e6c0
malloc 4 407976a8
malloc 64 4079eec0
malloc 5 407976b8
malloc 64 4079edc0
malloc 5 407976c0
malloc 64 4079ec00
malloc 4 407976c8
malloc 64 4079e940
malloc 4 407976d0
malloc 64 4079e980
malloc 3 407976d8
malloc 64 4079e9c0
malloc 4 407976e0
malloc 64 4079ea00
malloc 3 407976e8
malloc 8 407976f0
malloc 16 407985c0
malloc 8 407976f8
malloc 64 4079ea40
malloc 128 40796200
malloc 64 4079ea40
malloc 64 4079ea80
malloc 53 4079eac0
malloc 3 407976f0
malloc 144 40799dc0
malloc 64 4079eb00
malloc 64 4079eb40
malloc 55 4079eb80
malloc 3 407976f8
malloc 33 40af53c0
malloc 1 40797700
malloc 64 4079ebc0
malloc 1 40797708
malloc 4 40797710
malloc 64 4079ec40
malloc 3 40797700
malloc 64 4079ec80
malloc 3 40797718
malloc 256 407b7500
realloc 514 40adb000
realloc 257 407a0040
malloc 24 407a4ec0
malloc 257 407a0180
malloc 4 40797720
malloc 1024 407bf000
malloc 9 407985b0
malloc 4 40797170
malloc 4 40797650
malloc 4 40797680
malloc 328 407b1600
malloc 24 407a4e20
malloc 245 407b7500
malloc 48 40af53c0
malloc 4 40797688
malloc 8 40797698
malloc 5 407976a0
malloc 16 407985c0
malloc 24 407a4ea0
malloc 17 407a4ec0
malloc 4 407976a0
malloc 241 407b7900
malloc 1 40797698
malloc 17 407a4ee0
malloc 240 407b7600
malloc 24 407a4f00
malloc 228 407b7800
malloc 48 40af53f0
malloc 4 40797670
malloc 228 407b7600
malloc 8 40797698
malloc 5 407976a8
malloc 16 407985c0
malloc 5 40797698
malloc 24 407a4ee0
malloc 21 407a4f20
malloc 48 40af5420
malloc 4 40797698
malloc 220 407b8000
malloc 24 407a4f40
malloc 220 407b80e0
malloc 48 40af5450
malloc 4 407976a8
malloc 220 407b81c0
malloc 24 407a4f40
malloc 8 407976a8
malloc 4 407976b0
malloc 256 407b7700
malloc 112 40ac2150
malloc 8 407976a0
malloc 16 407985c0
malloc 6 40797670
malloc 11 407985d0
malloc 5 40797698
malloc 56 4079ee00
malloc 8 407976a8
malloc 25 407a4ea0
malloc 33 40af5480
malloc 40 40af54b0
malloc 11 407985e0
malloc 45 40af54e0
malloc 40 40af5510
malloc 9 407985f0
malloc 45 40af5540
malloc 16 40798600
malloc 48 40af5570
malloc 4 407976b8
malloc 11 40798610
malloc 9 40798610
malloc 24 407a4e20
malloc 45 40af55a0
malloc 4 40797170
malloc 44 40af5510
malloc 24 407a4ea0
malloc 33 40af5540
malloc 4 40797650
malloc 33 40af5510
malloc 17 407a4e20
malloc 24 407a4ea0
malloc 17 407a4f40
malloc 4 40797170
malloc 17 407a4ec0
malloc 17 407a4e20
malloc 24 407a4ea0
malloc 17 407a4f40
malloc 4 40797170
malloc 17 407a4f00
malloc 5 40797170
malloc 33 40af55a0
realloc 64 4079ee00
malloc 37 40af55a0
realloc 128 40796200
malloc 33 40af55a0
malloc 8 40797170
malloc 8 40797650
malloc 1024 407bf400
malloc 9 407985b0
realloc 1024 407bf800
malloc 1024 407bfc00
malloc 804 40ad4380
malloc 21 407a4e20
malloc 815 40ad4700
malloc 32 407a4ea0
malloc 8 40797170
malloc 64 4079ee00
malloc 33 40af5540
malloc 33 40af54b0
malloc 3 40797170
malloc 840 40ad4a80
malloc 1121 40ae0000
malloc 24 407a4f40
malloc 1121 40ae0500
malloc 4 40797650
malloc 1121 40ae0000
malloc 9 407985b0
malloc 1121 40ae0500
malloc 24 407a4e00
malloc 9 40798600
malloc 24 407a4ec0
malloc 1121 40ae0000
malloc 16 407985c0
malloc 40 40af52a0
malloc 33 40af5510
malloc 48 40af55a0
malloc 24 407a4f00
malloc 33 40af54b0
malloc 4 40797170
malloc 16 407985b0
malloc 40 40af5540
malloc 64 4079ee00
malloc 64 4079ee00
malloc 1136 40ae0500
`.trim();
//#endregion
//#region src/app/so/signer.ts
/**
* 纯 TS 执行 libmetasec_ml.so 生成签名头（等价 unidbg_work/medusa_pure.py）。
*
* 只补「边界层」：JNI stub、libc/syscall、少量 unidbg 侧 hook（cntvct/时间/srand/keyfix）。
* 中间 5 千万条 AArch64 指令全部由 src/arm64/cpu.ts 解释执行，不 spawn python/java。
*/
const SO_BASE = 1073741824;
const FROZEN_SUB = 0;
const MONO_BASE_US = 1e6;
const MONO_STEP_US = 1e3;
const PID = 12345;
/** so+0x280a34（fread 返回点）回填 so+0x467310 的 16 字节 UUID 种子 */
const KEYFIX = Buffer.from("00112233445566778899aabbccddeeff", "hex");
/** i3.java 初始化配置里的 license（与 MsSign.java 的 LICENSE 常量一致） */
const LICENSE = "bo95dJizD1WFcV03zOuLzN5Pn1sFtVa3szqiVQmflMJTNW0p0Kpqfw8D4i0zUlfrou4kuYt/i0521YRygM83dwv/wn3DD+TMJF+QFzW9wb8Qq2/1B4jPMbObrDNdyMMukpAYqy1fLWtbLGVIPxsFsZegwQy5lsRX9h49PH/Qx8MwgYvWvH7ZTFLV28LwTWZiljQyBPaBE+TsyumEu0Y+JRkeidHFEYcVs0yRoa+xC004hugQhdPupIt6dBiWA4phsB3fNJZjFTAKGE1lPB4gzt6Qf+FmlgZBbRvT8zekxTV2HZ5dUvSutB2/0QpbHKAvWL4DRA==";
/** unidbg 生成的 jmethodID（跨运行稳定），用于识别落盘前已缓存在 so 内存里的方法 */
const KNOWN_METHODS = /* @__PURE__ */ new Map([
	[831212713, [
		"java/lang/String",
		"getBytes",
		"(Ljava/lang/String;)[B",
		"L"
	]],
	[2398682137, [
		"android/app/Application",
		"getPackageName",
		"()Ljava/lang/String;",
		""
	]],
	[798289427, [
		"com/bytedance/mobsec/metasec/ml/MS",
		"b",
		"(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
		"IIJLL"
	]],
	[495723679, [
		"java/lang/Boolean",
		"valueOf",
		"(Z)Ljava/lang/Boolean;",
		"Z"
	]],
	[439503871, [
		"java/lang/Long",
		"valueOf",
		"(J)Ljava/lang/Long;",
		"J"
	]],
	[1274697164, [
		"com/bytedance/mobsec/metasec/ml/MS",
		"a",
		"()V",
		""
	]]
]);
/** 「调用点 → JNI 语义」真值表（来自 unidbg 运行时日志 postjni2.txt） */
const SITE_SEM = /* @__PURE__ */ new Map([
	[2739204, "NewStringUTF"],
	[2739856, "NewStringUTF"],
	[2737432, "GetMethodID"],
	[2260224, "GetStaticMethodID"],
	[2737696, "CallObjectMethodV"],
	[2737648, "CallObjectMethodV"],
	[2739620, "GetArrayLength"],
	[2739684, "GetByteArrayRegion"],
	[2733548, "CallStaticObjectMethodV"],
	[2744924, "NewObjectArray"],
	[2745080, "SetObjectArrayElement"],
	[2745108, "SetObjectArrayElement"],
	[2737392, "ExceptionCheck"],
	[2737372, "GetObjectClass"]
]);
/** JavaVM 调用点 */
const VM_SITE = /* @__PURE__ */ new Map([
	[2735460, "VM_GetEnv"],
	[2735240, "VM_Attach"],
	[2735016, "VM_Detach"]
]);
/** JavaVM 表下标兜底（4=Attach 5=Detach 6=GetEnv 7=AttachAsDaemon） */
const VM_IDX_SEM = /* @__PURE__ */ new Map([
	[1004, "VM_Attach"],
	[1005, "VM_Detach"],
	[1006, "VM_GetEnv"],
	[1007, "VM_Attach"]
]);
/** 兜底：按 JNI 表下标（快照内存实测的语义） */
const IDX_SEM = /* @__PURE__ */ new Map([
	[167, "NewStringUTF"],
	[33, "GetMethodID"],
	[113, "GetStaticMethodID"],
	[53, "CallObjectMethodV"],
	[171, "GetArrayLength"],
	[200, "GetByteArrayRegion"],
	[115, "CallStaticObjectMethodV"],
	[172, "NewObjectArray"],
	[174, "SetObjectArrayElement"],
	[228, "ExceptionCheck"],
	[31, "GetObjectClass"],
	[26, "EnsureLocalCapacity"],
	[232, "GetObjectRefType"],
	[21, "NewGlobalRef"],
	[22, "DeleteGlobalRef"],
	[23, "DeleteLocalRef"],
	[19, "PushLocalFrame"],
	[20, "PopLocalFrame"],
	[17, "ExceptionOccurred"],
	[6, "FindClass"],
	[4, "GetVersion"],
	[215, "RegisterNatives"],
	[10, "GetSuperclass"],
	[176, "NewByteArray"],
	[184, "GetByteArrayElements"],
	[192, "ReleaseByteArrayElements"],
	[208, "SetByteArrayRegion"],
	[35, "CallObjectMethodV"],
	[169, "GetStringUTFChars"],
	[170, "ReleaseStringUTFChars"],
	[38, "CallBooleanMethodV"],
	[50, "CallIntMethodV"],
	[62, "CallVoidMethodV"]
]);
/** unidbg VaList64 的等价实现 */
var VaList = class {
	mem;
	shorty;
	stack;
	grTop;
	vrTop;
	grOffs;
	vrOffs;
	i = 0;
	constructor(mem, p, shorty) {
		this.mem = mem;
		this.shorty = shorty;
		this.stack = Number(mem.read(p, 8));
		this.grTop = Number(mem.read(p + 8, 8));
		this.vrTop = Number(mem.read(p + 16, 8));
		this.grOffs = s32(Number(mem.read(p + 24, 4)));
		this.vrOffs = s32(Number(mem.read(p + 28, 4)));
	}
	gprAddr() {
		if (this.grOffs & -2147483648) {
			if (this.grOffs + 8 <= 0) {
				const a = this.grTop + this.grOffs;
				this.grOffs += 8;
				return a;
			}
			const a = this.stack;
			this.grOffs += 8;
			this.stack = this.stack + 11 & -8;
			return a;
		}
		const a = this.stack;
		this.stack = this.stack + 11 & -8;
		return a;
	}
	vrAddr() {
		if (this.vrOffs & -2147483648) {
			if (this.vrOffs + 16 <= 0) {
				const a = this.vrTop + this.vrOffs;
				this.vrOffs += 16;
				return a;
			}
			const a = this.stack;
			this.vrOffs += 16;
			this.stack = this.stack + 15 & -8;
			return a;
		}
		const a = this.stack;
		this.stack = this.stack + 15 & -8;
		return a;
	}
	next() {
		const t = this.shorty[this.i];
		this.i += 1;
		if (t === "J") return Number(this.mem.read(this.gprAddr(), 8));
		if ("BCISZL".includes(t)) return Number(this.mem.read(this.gprAddr(), 4));
		if ("DF".includes(t)) return Number(this.mem.read(this.vrAddr(), 8));
		throw new Error(`va_list: unsupported shorty ${t}`);
	}
	/** 取下一个整数参数（printf 用；size=4/8） */
	int(size) {
		return Number(this.mem.read(this.gprAddr(), size));
	}
	/** 取下一个双精度参数（printf 的 %f 等） */
	fp() {
		const dv = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(8));
		dv.setBigUint64(0, this.mem.read(this.vrAddr(), 8), true);
		return dv.getFloat64(0, true);
	}
};
function s32(v) {
	v &= 4294967295;
	return v & 2147483648 ? v - 4294967296 : v;
}
/** 按 JNI 签名求 shorty（L 开头/数组都算 L） */
function shorty(sig) {
	const out = [];
	let i = 1;
	while (i < sig.length && sig[i] !== ")") {
		const c = sig[i];
		if (c === "L") {
			i = sig.indexOf(";", i) + 1;
			out.push("L");
			continue;
		}
		if (c === "[") {
			out.push("L");
			while (sig[i] === "[") i += 1;
			if (sig[i] === "L") i = sig.indexOf(";", i) + 1;
			else i += 1;
			continue;
		}
		out.push(c);
		i += 1;
	}
	return out.join("");
}
/** so+0x2aa800 的 8 字节混合（X-Medusa 明文 fl 的第 4 个字段） */
function flHash(v) {
	let w9 = 2102535;
	const st = /* @__PURE__ */ new Uint8Array(8);
	new DataView(st.buffer).setUint32(0, v >>> 0, true);
	for (let i = 0; i < 8; i++) {
		const b = st[i];
		if (i % 2 === 0) {
			w9 = (w9 ^ w9 << 6 ^ w9 >>> 4) >>> 0;
			w9 = (w9 ^ b) >>> 0;
		} else {
			const w11 = (b & 4095 | (w9 & 1048575) << 12) >>> 0;
			w9 = (w9 ^ w9 >>> 7) >>> 0;
			w9 = ~(w9 ^ w11) >>> 0;
		}
	}
	return w9;
}
var SoSigner = class {
	opts;
	mem = new PageMem();
	cpu;
	segs = [];
	regs = {};
	/** 快照寄存器原值：64 位十六进制串直接转 BigInt，避免 Number 丢精度（x29/x1 常超 2^53） */
	regs64 = /* @__PURE__ */ new Map();
	base = SO_BASE;
	ts;
	pid;
	srand;
	keyfix;
	verbose;
	trace;
	tailN;
	tracePc;
	regPc;
	watchSpec;
	ctxTrace = [];
	/** 基本块级对拍（SO_BBLOG）：是否在记录、上一条 pc、块首序列 */
	bbActive = false;
	bbPrev = -1;
	bbBlocks = [];
	bbReads = [];
	bbWrites = [];
	/** SO_RFLOG：VM regfile 写入序列 */
	rfLog = [];
	/** SO_RFLOG 门控：memset(0x40ad4380, 0, 0x2e3) 之后开始记录 */
	rfOn = false;
	/** SO_WLOG：指定区间的写入序列（含 libc stub 的 C/F 记录） */
	wlog = [];
	/** SO_LDRBLOG：VM ldrb（0x189a98）读取序列 */
	ldrbLog = [];
	stepDump;
	tailBuf = [];
	maxSteps;
	/** 块级 JIT（无调试开关时启用） */
	jit = null;
	/** 建 JIT 时的 pcHooks 数量（变了就重建，避免漏掉新装的钩子） */
	jitHooks = -1;
	/** 块被遇到多少次才编译（SO_JITTHRESH 可覆盖，调优用） */
	jitThresh = Number(process.env.SO_JITTHRESH ?? 64) || 64;
	coldLibs = [];
	coldMeta;
	coldGlobals = /* @__PURE__ */ new Map();
	coldNative = /* @__PURE__ */ new Map();
	/** GetByteArrayElements 借出的线性内存（0x30000000 起每块 64KB） */
	arrMem = 805306368;
	/** 借出指针 → 对应 jarray 句柄，Release 时按 mode 拷回 */
	arrPtr = /* @__PURE__ */ new Map();
	coldInitArray = [];
	coldJniOnLoad = 0;
	coldStarted = false;
	coldEnv = 4294841088;
	coldVm = 4294841104;
	coldSentinel = 192;
	coldSp = Number(process.env.SO_SP ?? 3221223168);
	mmapNext = 1090519040;
	coldClassHandle = 1778384897;
	coldApplication = 1778384898;
	coldEntry = 0;
	coldUnknown = /* @__PURE__ */ new Set();
	/** 最近 512 条指令 pc 的环形缓冲（仅用于异常诊断） */
	coldTail = new Array(512).fill(0);
	coldTailIdx = 0;
	coldInLibc = false;
	/** 冷启动的 bump 分配器（libc 的 dlmalloc 会走 SIMD，只能自己实现） */
	coldHeap = Number(process.env.SO_HEAP_BASE ?? 1375731712);
	coldAllocs = /* @__PURE__ */ new Map();
	/** 签名阶段按 oracle 的 dlmalloc 序列回放堆地址 */
	replayOn = false;
	replayIdx = 0;
	replayList = [];
	coldKeySeq = 1;
	coldTls = /* @__PURE__ */ new Map();
	coldDepth = 0;
	/** 假 FILE* → fd */
	coldFiles = /* @__PURE__ */ new Map();
	urlHandle = 0;
	entryPc = 0;
	retPc = 0;
	objs = /* @__PURE__ */ new Map();
	nextHandle = 1879048192;
	methods = new Map(KNOWN_METHODS);
	midOf = /* @__PURE__ */ new Map();
	classes = /* @__PURE__ */ new Map();
	fds = /* @__PURE__ */ new Map();
	nextFd = 3;
	tick = 1048576;
	monoUs = -1;
	/** 只跑初始化（warmUp）：停在 getFeatureHash 入口前 */
	warmOnly = false;
	/** 预热基线：init 完成时的内存页与对象句柄状态，signFast 每次恢复它 */
	baseline = null;
	imm2jni = /* @__PURE__ */ new Map();
	jni2imm = /* @__PURE__ */ new Map();
	/** 返回值 true 表示已模拟完整条指令（pc 已推进），false 表示只改了现场、仍需执行该指令 */
	pcHooks = /* @__PURE__ */ new Map();
	jniCount = {};
	svcLog = [];
	nstr = [];
	/** tracePc 打开时记录的 pc 序列 */
	pcSeq = [];
	stopReason = "";
	donePc = null;
	steps = 0;
	/** 与 Python oracle 对齐的指令序号（pcHook 命中也计数） */
	pcIndex = 0;
	constructor(opts) {
		this.opts = opts;
		this.ts = opts.ts ?? 1794343920;
		this.pid = opts.pid ?? PID;
		this.srand = opts.srand ?? (process.env.DY_SRAND ? Number(process.env.DY_SRAND) : null);
		this.keyfix = opts.keyfix ?? KEYFIX;
		this.verbose = opts.verbose ?? false;
		this.trace = opts.trace ?? 0;
		this.tailN = opts.tail ?? 0;
		this.tracePc = opts.tracePc ?? 0;
		this.regPc = opts.regPc ?? 0;
		this.watchSpec = opts.watch;
		this.stepDump = opts.stepDump ?? 0;
		this.maxSteps = opts.maxSteps ?? 2e8;
		for (const [mid, v] of KNOWN_METHODS) this.midOf.set(`${v[0]}\u0000${v[1]}\u0000${v[2]}`, mid);
	}
	load() {
		const dir = this.opts.stateDir ?? "";
		const files = /* @__PURE__ */ new Map();
		for (const line of readFileSync(join(dir, "memmap.txt"), "utf8").split(/\r?\n/)) {
			const t = line.trim();
			if (!t) continue;
			const [name, b, s] = t.split(/\s+/);
			const base = parseInt(b, 16);
			this.segs.push([base, parseInt(s, 16)]);
			files.set(base, name);
		}
		for (const [b, s] of this.segs) this.mem.map(b, s + 4095 & -4096);
		for (const [b, name] of files) this.mem.load(b, readFileSync(join(dir, name)));
		for (const line of readFileSync(join(dir, "regs.txt"), "utf8").split(/\r?\n/)) {
			const p = line.trim().split(/\s+/);
			if (p.length === 2) {
				const v = BigInt(`0x${p[1]}`);
				this.regs64.set(p[0], v);
				this.regs[p[0]] = Number(v);
			}
		}
		this.urlHandle = this.regs.x5;
		this.base = this.regs.base ?? 1073741824;
		this.objs.set(this.urlHandle, {
			kind: "string",
			val: this.opts.url
		});
		if (this.opts.bodyBytes) this.regs64.set("x6", BigInt(this.newHandle({
			kind: "bytearray",
			val: this.opts.bodyBytes
		})));
		else if (this.opts.body) this.regs64.set("x6", BigInt(this.newHandle({
			kind: "string",
			val: this.opts.body
		})));
		this.objs.set(561480862, {
			kind: "object",
			val: "application"
		});
		this.cpu = new Cpu(this.mem);
		if (this.watchSpec) {
			const [lo, len] = this.watchSpec;
			this.mem.watch = {
				lo,
				hi: lo + len,
				cb: (a, s, v) => console.log(`[memwr] #${this.steps} pc=+0x${(this.cpu.pc - this.base).toString(16)} addr=0x${a.toString(16)} size=${s} v=0x${v.toString(16)}`)
			};
		}
	}
	valid(addr, n = 1) {
		for (const [b, s] of this.segs) if (b <= addr && addr + n <= b + s) return true;
		return false;
	}
	setRegs() {
		const cpu = this.cpu;
		const g = (k) => this.regs64.get(k) ?? 0n;
		for (let i = 0; i < 29; i++) cpu.x[i] = g(`x${i}`);
		cpu.x[29] = g("x29");
		cpu.x[30] = g("x30");
		cpu.x[31] = g("sp");
		cpu.pc = Number(g("pc"));
		cpu.tpidr = g("tpidr");
		this.entryPc = cpu.pc;
		this.retPc = Number(cpu.x[30]);
	}
	/** so 在 init_array 里把冻结毫秒缓存进若干全局，X-Medusa 的「距初始化耗时」取的就是它 */
	patchInitTime() {
		const ms = this.ts * 1e3 + Math.floor(FROZEN_SUB / 1e3);
		for (const a of [
			"469b98",
			"798020",
			"ac2050",
			"ad1008",
			"ad12b0",
			"797118"
		]) if (a === "797118") this.mem.write(this.base + 7958808, 4, BigInt(this.ts));
		else this.mem.write(this.base + parseInt(a, 16), 8, BigInt(ms));
		const ms64 = BigInt(ms);
		const f2 = Number(ms64 & 4294967295n ^ ms64 >> 32n & 4294967295n) >>> 0;
		const f3 = ((f2 & 255) << 24 | (f2 & 65280) << 8 | f2 >>> 8 & 65280 | f2 >>> 24) >>> 0;
		const f4 = flHash(f3);
		this.mem.write(this.base + 4562592, 4, BigInt(f2));
		this.mem.write(this.base + 4562596, 4, BigInt(f3));
		this.mem.write(this.base + 4562600, 4, BigInt(f4));
	}
	/** 从 JNIEnv 表里解出每个 stub 的 svc imm（imm → 表下标） */
	decodeJniTable() {
		const env = this.regs.x0;
		let tbl;
		try {
			tbl = Number(this.mem.read(env, 8));
		} catch {
			return;
		}
		if (this.verbose) console.log(`[jni] JNIEnv=0x${env.toString(16)} table=0x${tbl.toString(16)}`);
		for (let i = 0; i < 260; i++) {
			let p;
			try {
				p = Number(this.mem.read(tbl + 8 * i, 8));
			} catch {
				break;
			}
			if (!this.valid(p, 4)) continue;
			const w = this.mem.fetch(p);
			if ((w & 4292870175) >>> 0 === 3556769793) {
				const imm = w >>> 5 & 65535;
				this.imm2jni.set(imm, i);
				this.jni2imm.set(i, imm);
			}
		}
		if (this.verbose) {
			const list = [...this.imm2jni.entries()].sort((a, b) => a[1] - b[1]);
			console.log("[jni] stubs: " + list.map(([imm, i]) => `${i}->0x${imm.toString(16)}`).join(", "));
		}
	}
	installHooks() {
		for (const off of [
			2172060,
			2172084,
			2172180,
			2172204,
			2172300,
			2172324,
			2172404,
			2172428
		]) this.pcHooks.set(this.base + off, (cpu) => {
			cpu.x[10] = BigInt(this.tick);
			cpu.x[11] = BigInt(this.tick);
			this.tick += 1e3;
			cpu.pc = this.base + off + 4;
			return true;
		});
		this.pcHooks.set(1080048356, (cpu) => {
			const lr = Number(cpu.x[30]);
			const a0 = Number(cpu.x[0]);
			if (a0) this.mem.write(a0, 8, BigInt(this.ts));
			cpu.x[0] = BigInt(this.ts);
			cpu.pc = lr;
			return true;
		});
		this.pcHooks.set(1079826516, (cpu) => {
			const lr = Number(cpu.x[30]);
			const clk = Number(cpu.x[0]);
			const tp = Number(cpu.x[1]);
			const [sec, nsec] = clk === 0 || clk === 5 ? [this.ts, FROZEN_SUB] : this.monoTime();
			if (tp) {
				this.mem.write(tp, 8, BigInt(sec));
				this.mem.write(tp + 8, 8, BigInt(nsec));
			}
			cpu.x[0] = 0n;
			cpu.pc = lr;
			return true;
		});
		this.pcHooks.set(1079826660, (cpu) => {
			const lr = Number(cpu.x[30]);
			const tv = Number(cpu.x[0]);
			if (tv) {
				this.mem.write(tv, 8, BigInt(this.ts));
				this.mem.write(tv + 8, 8, BigInt(FROZEN_SUB));
			}
			cpu.x[0] = 0n;
			cpu.pc = lr;
			return true;
		});
		this.pcHooks.set(this.base + 2726164, (cpu) => {
			if (this.srand === null) {
				if (this.verbose) console.log(`[srand] seed = 0x${Number(cpu.x[0]).toString(16)}（沿用 so 自己算的）`);
				return false;
			}
			if (this.verbose) console.log(`[srand] seed -> 0x${this.srand.toString(16)} @+0x299914`);
			cpu.x[0] = BigInt(this.srand);
			return false;
		});
		this.pcHooks.set(this.base + 2624052, () => {
			if (this.verbose) console.log("[keyfix] so+0x467310 <- " + Buffer.from(this.keyfix).toString("hex"));
			this.mem.load(this.base + 4616976, this.keyfix);
			return false;
		});
	}
	monoTime() {
		if (this.monoUs < 0) this.monoUs = MONO_BASE_US;
		else this.monoUs += MONO_STEP_US;
		return [Math.floor(this.monoUs / 1e6), this.monoUs % 1e6 * 1e3];
	}
	newHandle(obj) {
		const h = this.nextHandle;
		this.nextHandle += 16;
		this.objs.set(h, obj);
		return h;
	}
	obj(h) {
		return this.objs.get(h);
	}
	ret(cpu, val) {
		cpu.x[0] = BigInt.asUintN(64, BigInt(val));
		cpu.pc = Number(cpu.x[30]);
	}
	onSvc(cpu, imm) {
		if (imm >= 256) this.doJni(cpu, imm);
		else if (imm === 0) this.doSyscall(cpu, Number(cpu.x[8]));
		else this.doSyscall(cpu, imm);
	}
	doJni(cpu, imm) {
		const idx = this.imm2jni.get(imm);
		const x1 = Number(cpu.x[1]);
		const x2 = Number(cpu.x[2]);
		const x3 = Number(cpu.x[3]);
		const x4 = Number(cpu.x[4]);
		const off = Number(cpu.x[30]) - this.base;
		const sem = SITE_SEM.get(off) ?? VM_SITE.get(off) ?? (idx !== void 0 ? idx >= 1e3 ? VM_IDX_SEM.get(idx) : IDX_SEM.get(idx) : void 0);
		const key = sem ?? "?";
		this.jniCount[key] = (this.jniCount[key] ?? 0) + 1;
		if (this.verbose) console.log(`[jni] +0x${off.toString(16)} ${key} (idx=${idx} imm=0x${imm.toString(16)})`);
		if (sem === "VM_GetEnv" || sem === "VM_Attach") {
			if (x1) this.mem.write(x1, 8, BigInt(this.envPtr()));
			if (this.verbose) console.log(`[vm] ${sem} -> env=0x${this.envPtr().toString(16)}`);
			this.ret(cpu, 0);
			return;
		}
		if (sem === "VM_Detach") {
			this.ret(cpu, 0);
			return;
		}
		if (sem === "NewStringUTF") {
			const txt = this.mem.cstr(x1);
			this.nstr.push(txt);
			if (process.env.SO_NSTRADDR) writeFileSync("d:/there/douyinhook/unidbg_work/nstrlog.txt", `0x${x1.toString(16)} len=${txt.length}\t${txt.length <= 60 ? txt : txt.slice(0, 60) + "..."}\n`, { flag: "a" });
			if (this.verbose) console.log(`[nstr] ${JSON.stringify(txt.length <= 80 ? txt : txt.slice(0, 80) + "...")}`);
			this.ret(cpu, this.newHandle({
				kind: "string",
				val: txt
			}));
			return;
		}
		if (sem === "GetStringUTFChars") {
			const o = this.obj(x1);
			const buf = Buffer.from(`${o && o.kind === "string" ? o.val : ""}\0`, "utf8");
			const p = this.arrMem;
			this.arrMem += 65536;
			this.mem.map(p, Math.max(1, buf.length));
			this.mem.load(p, new Uint8Array(buf));
			if (x2) this.mem.write(x2, 4, 1n);
			this.ret(cpu, p);
			return;
		}
		if (sem === "ReleaseStringUTFChars") {
			this.ret(cpu, 0);
			return;
		}
		if (sem === "GetMethodID" || sem === "GetStaticMethodID") {
			const name = this.mem.cstr(x2);
			const sig = this.mem.cstr(x3);
			const cls = this.classes.get(x1);
			let mid = cls !== void 0 ? this.midOf.get(`${cls}\u0000${name}\u0000${sig}`) : void 0;
			if (mid === void 0) {
				for (const [m2, v] of this.methods) if (v[1] === name && v[2] === sig) {
					mid = m2;
					break;
				}
			}
			if (mid === void 0) {
				mid = this.nextHandle;
				this.nextHandle += 16;
			}
			const c = cls ?? "?";
			this.methods.set(mid, [
				c,
				name,
				sig,
				shorty(sig)
			]);
			this.midOf.set(`${cls ?? "?"}\u0000${name}\u0000${sig}`, mid);
			if (this.verbose) console.log(`[mid] ${cls ?? "0x" + x1.toString(16)}.${name}${sig} => 0x${mid.toString(16)}`);
			this.ret(cpu, mid);
			return;
		}
		if (sem === "CallObjectMethodV") {
			const o = this.obj(x1);
			const info = this.methods.get(x2);
			const name = info ? info[1] : "?";
			if (this.verbose) console.log(`[call] ${name}(${o ? o.kind : "null"})`);
			if (name === "getBytes") {
				const data = o && o.kind === "string" ? Buffer.from(o.val, "utf8") : Buffer.alloc(0);
				this.ret(cpu, this.newHandle({
					kind: "bytearray",
					val: new Uint8Array(data)
				}));
				return;
			}
			if (name === "getPackageName") {
				this.ret(cpu, this.newHandle({
					kind: "string",
					val: "com.ss.android.ugc.aweme"
				}));
				return;
			}
			if (name === "getClassLoader") {
				this.ret(cpu, this.newHandle({
					kind: "object",
					val: "classloader"
				}));
				return;
			}
			if (name === "findClass" || name === "loadClass") {
				const va = new VaList(this.mem, x3, info ? info[3] : "L");
				const a = this.obj(va.next());
				const nm = a && a.kind === "string" ? a.val.replace(/\./g, "/") : "?";
				const h = this.newHandle({
					kind: "class",
					val: nm
				});
				this.classes.set(h, nm);
				this.ret(cpu, h);
				return;
			}
			const va = info ? new VaList(this.mem, x3, info[3]) : null;
			const r = this.jcall(o, name, va, info ? info[3] : "");
			if (r !== void 0) {
				this.ret(cpu, r);
				return;
			}
			this.ret(cpu, 0);
			return;
		}
		if (sem === "CallBooleanMethodV" || sem === "CallIntMethodV" || sem === "CallLongMethodV" || sem === "CallVoidMethodV") {
			const o = this.obj(x1);
			const info = this.methods.get(x2);
			const va = info ? new VaList(this.mem, x3, info[3]) : null;
			const r = this.jcall(o, info ? info[1] : "?", va, info ? info[3] : "");
			if (sem === "CallVoidMethodV") {
				this.ret(cpu, 0);
				return;
			}
			const v = r ? this.obj(r)?.val : void 0;
			const n = typeof v === "boolean" ? v ? 1 : 0 : Number(v ?? 0);
			this.ret(cpu, sem === "CallBooleanMethodV" ? n !== 0 ? 1 : 0 : n);
			return;
		}
		if (sem === "CallStaticObjectMethodV") {
			const info = this.methods.get(x2);
			const name = info ? info[1] : "?";
			const cls = info ? info[0] : "?";
			if (info && name === "b" && cls.includes("MS")) {
				const va = new VaList(this.mem, x3, info[3]);
				const op = va.next();
				va.next();
				va.next();
				const a3 = va.next();
				const a4 = va.next();
				if (this.verbose) console.log(`[MS.b] op=${op} arg3=${JSON.stringify(this.obj(a3)?.val ?? null)} arg4=${JSON.stringify(this.obj(a4)?.val ?? null)}`);
				this.ret(cpu, this.msB(op, a3, a4));
				return;
			}
			if (name === "valueOf" && cls === "java/lang/Boolean") {
				const va = new VaList(this.mem, x3, info[3]);
				this.ret(cpu, this.newHandle({
					kind: "boolean",
					val: va.next() !== 0
				}));
				return;
			}
			if (name === "valueOf" && cls === "java/lang/Long") {
				const va = new VaList(this.mem, x3, info[3]);
				this.ret(cpu, this.newHandle({
					kind: "long",
					val: va.next()
				}));
				return;
			}
			if (this.verbose) console.log(`[call] static ${cls}.${name} -> null`);
			this.ret(cpu, 0);
			return;
		}
		if (sem === "GetArrayLength") {
			const o = this.obj(x1);
			const n = o && (o.kind === "bytearray" || o.kind === "objarray") ? o.kind === "bytearray" ? o.val.length : o.val.length : 0;
			this.ret(cpu, n);
			return;
		}
		if (sem === "NewObjectArray") {
			this.ret(cpu, this.newHandle({
				kind: "objarray",
				val: new Array(x1 & 4294967295).fill(0)
			}));
			return;
		}
		if (sem === "SetObjectArrayElement") {
			const arr = this.obj(x1);
			const i = x2 & 4294967295;
			if (arr && arr.kind === "objarray" && i >= 0 && i < arr.val.length) arr.val[i] = x3;
			if (this.verbose) {
				const v = this.obj(x3);
				console.log(`[set] [${i}] = ${JSON.stringify(v?.val ?? null)}`);
			}
			this.ret(cpu, 0);
			return;
		}
		if (sem === "GetByteArrayRegion") {
			const arr = this.obj(x1);
			const start = x2 & 4294967295;
			const ln = x3 & 4294967295;
			if (arr && arr.kind === "bytearray") {
				const src = arr.val;
				const buf = new Uint8Array(ln);
				buf.set(src.subarray(start, Math.min(start + ln, src.length)));
				this.mem.load(x4, buf);
			}
			this.ret(cpu, 0);
			return;
		}
		if (sem === "NewByteArray") {
			this.ret(cpu, this.newHandle({
				kind: "bytearray",
				val: new Uint8Array(x1 & 4294967295)
			}));
			return;
		}
		if (sem === "GetByteArrayElements") {
			const o = this.obj(x1);
			const src = o && o.kind === "bytearray" ? o.val : /* @__PURE__ */ new Uint8Array(0);
			const p = this.arrMem;
			this.arrMem += 65536;
			this.mem.map(p, Math.max(1, src.length));
			this.mem.load(p, src);
			this.arrPtr.set(p, x1);
			if (x2) this.mem.write(x2, 4, 1n);
			this.ret(cpu, p);
			return;
		}
		if (sem === "ReleaseByteArrayElements") {
			const h = this.arrPtr.get(x2);
			const o = h !== void 0 ? this.obj(h) : void 0;
			if (o && o.kind === "bytearray") {
				const dst = o.val;
				for (let i = 0; i < dst.length; i++) dst[i] = this.mem.ld8(x2 + i);
			}
			this.arrPtr.delete(x2);
			this.ret(cpu, 0);
			return;
		}
		if (sem === "SetByteArrayRegion") {
			const o = this.obj(x1);
			if (o && o.kind === "bytearray") {
				const dst = o.val;
				const start = x2 & 4294967295;
				const ln = x3 & 4294967295;
				for (let i = 0; i < ln && start + i < dst.length; i++) dst[start + i] = this.mem.ld8(x4 + i);
			}
			this.ret(cpu, 0);
			return;
		}
		if (sem === "GetObjectClass") {
			const o = this.obj(x1);
			const nm = this.className(o);
			const h = this.newHandle({
				kind: "class",
				val: nm
			});
			this.classes.set(h, nm);
			this.ret(cpu, h);
			return;
		}
		if (sem === "FindClass") {
			const nm = this.mem.cstr(x1);
			if (this.verbose) console.log(`[find] ${nm}`);
			const h = this.newHandle({
				kind: "class",
				val: nm
			});
			this.classes.set(h, nm);
			this.ret(cpu, h);
			return;
		}
		if (sem === "GetSuperclass") {
			const h = this.newHandle({
				kind: "class",
				val: "java/lang/Object"
			});
			this.classes.set(h, "java/lang/Object");
			this.ret(cpu, h);
			return;
		}
		if (sem === "NewGlobalRef") {
			this.ret(cpu, x1);
			return;
		}
		if (sem === "GetObjectRefType") {
			this.ret(cpu, 1);
			return;
		}
		if (sem === "GetVersion") {
			this.ret(cpu, 65542);
			return;
		}
		if (sem === "RegisterNatives") {
			if (this.opts.cold) {
				const n2 = x3 >>> 0;
				if (n2 > 0 && n2 < 200 && this.methodsAt(x2)) this.coldRegisterNatives(x2, n2);
				else this.coldRegisterNatives(x3, x4);
			}
			this.ret(cpu, 0);
			return;
		}
		if (sem === "ExceptionCheck" || sem === "ExceptionClear" || sem === "ExceptionOccurred" || sem === "DeleteGlobalRef" || sem === "DeleteLocalRef" || sem === "EnsureLocalCapacity" || sem === "PushLocalFrame" || sem === "PopLocalFrame") {
			this.ret(cpu, 0);
			return;
		}
		if (this.verbose) console.log(`[jni] !! unimplemented ${key} (idx=${idx} imm=0x${imm.toString(16)}) x1=0x${x1.toString(16)} x2=0x${x2.toString(16)} x3=0x${x3.toString(16)}`);
		this.ret(cpu, 0);
	}
	/** MsJni.callStaticObjectMethodV 里 MS.b 的等价语义 */
	msB(op, a3, a4) {
		if (op === 65537) return this.newHandle({
			kind: "string",
			val: "40.5.0"
		});
		if (op === 65538) return this.newHandle({
			kind: "string",
			val: "com.ss.android.ugc.aweme"
		});
		if (op === 65539) return this.newHandle({
			kind: "string",
			val: "/data/user/0/com.ss.android.ugc.aweme/files"
		});
		if (op === 33554433 || op === 33554434) return this.newHandle({
			kind: "boolean",
			val: true
		});
		return 0;
	}
	/** 句柄对应的 Java 类名（native 会用它取 GetObjectClass 结果再反射找方法） */
	className(o) {
		if (!o) return "?";
		switch (o.kind) {
			case "string": return "java/lang/String";
			case "bytearray": return "[B";
			case "boolean": return "java/lang/Boolean";
			case "long": return "java/lang/Long";
			case "map": return "java/util/HashMap";
			case "set": return "java/util/HashSet";
			case "iter": return "java/util/Iterator";
			case "entry": return "java/util/Map$Entry";
			case "json": return "org/json/JSONObject";
			case "class": return "java/lang/Class";
			default: return "java/lang/Object";
		}
	}
	/** 句柄 → 字符串（Map 键比较用） */
	str(h) {
		const o = this.obj(h);
		if (!o) return "";
		return typeof o.val === "string" ? o.val : String(o.val);
	}
	/** JS 值 → Java 句柄 */
	jval(v) {
		if (v === null || v === void 0) return 0;
		if (typeof v === "string") return this.newHandle({
			kind: "string",
			val: v
		});
		if (typeof v === "boolean") return this.newHandle({
			kind: "boolean",
			val: v
		});
		if (typeof v === "number") return this.newHandle({
			kind: "long",
			val: v
		});
		if (Array.isArray(v)) return this.newHandle({
			kind: "objarray",
			val: v.map((x) => this.jval(x))
		});
		return this.newHandle({
			kind: "json",
			val: v
		});
	}
	/**
	* 通用 Java 侧方法：HashMap / HashSet / Iterator / Map$Entry / JSONObject。
	* 未命中返回 undefined（调用方回 0）。
	*/
	jcall(o, name, va, sig) {
		if (!o) return void 0;
		if (name === "toString") {
			const v = o.val;
			return this.newHandle({
				kind: "string",
				val: typeof v === "string" ? v : JSON.stringify(v ?? null)
			});
		}
		if (name === "hashCode") return this.newHandle({
			kind: "long",
			val: 0
		});
		if (name === "equals") return this.newHandle({
			kind: "boolean",
			val: true
		});
		if (name === "getClass") return this.newHandle({
			kind: "class",
			val: this.className(o)
		});
		if (o.kind === "map") {
			const pairs = o.val;
			if (name === "size") return this.newHandle({
				kind: "long",
				val: pairs.length
			});
			if (name === "isEmpty") return this.newHandle({
				kind: "boolean",
				val: pairs.length === 0
			});
			if (name === "entrySet" || name === "keySet" || name === "values") {
				const items = name === "entrySet" ? pairs.map(([k, v]) => this.newHandle({
					kind: "entry",
					val: [k, v]
				})) : pairs.map(([k, v]) => name === "keySet" ? k : v);
				return this.newHandle({
					kind: "set",
					val: items
				});
			}
			if (name === "get" && va) {
				const key = this.str(va.next());
				if (this.verbose) console.log(`[map] get(${key})`);
				const hit = pairs.find(([k]) => this.str(k) === key);
				return hit ? hit[1] : 0;
			}
			if (name === "containsKey" && va) {
				const key = this.str(va.next());
				return this.newHandle({
					kind: "boolean",
					val: pairs.some(([k]) => this.str(k) === key)
				});
			}
			if (name === "put" && va) {
				const kh = va.next();
				const vh = va.next();
				const key = this.str(kh);
				const i = pairs.findIndex(([k]) => this.str(k) === key);
				if (i < 0) {
					pairs.push([kh, vh]);
					return 0;
				}
				const old = pairs[i][1];
				pairs[i][1] = vh;
				return old;
			}
			return;
		}
		if (o.kind === "set") {
			const items = o.val;
			if (name === "size") return this.newHandle({
				kind: "long",
				val: items.length
			});
			if (name === "isEmpty") return this.newHandle({
				kind: "boolean",
				val: items.length === 0
			});
			if (name === "iterator") return this.newHandle({
				kind: "iter",
				val: {
					items,
					i: 0
				}
			});
			return;
		}
		if (o.kind === "iter") {
			const it = o.val;
			if (name === "hasNext") return this.newHandle({
				kind: "boolean",
				val: it.i < it.items.length
			});
			if (name === "next") return it.i < it.items.length ? it.items[it.i++] : 0;
			return;
		}
		if (o.kind === "entry") {
			const [k, v] = o.val;
			if (name === "getKey") return k;
			if (name === "getValue") return v;
			return;
		}
		if (o.kind === "json") {
			const j = o.val;
			const get = (key) => Object.prototype.hasOwnProperty.call(j, key) ? j[key] : void 0;
			if (name === "length" || name === "size") return this.newHandle({
				kind: "long",
				val: Object.keys(j).length
			});
			if (name === "names" || name === "keys") {
				const items = Object.keys(j).map((k) => this.newHandle({
					kind: "string",
					val: k
				}));
				return this.newHandle({
					kind: "iter",
					val: {
						items,
						i: 0
					}
				});
			}
			if (name === "has" && va) {
				const key = this.str(va.next());
				return this.newHandle({
					kind: "boolean",
					val: get(key) !== void 0
				});
			}
			if (name === "isNull" && va) {
				const v = get(this.str(va.next()));
				return this.newHandle({
					kind: "boolean",
					val: v === null || v === void 0
				});
			}
			if (!va) return void 0;
			const key = this.str(va.next());
			const v = get(key);
			if (this.verbose) console.log(`[json] ${name}(${key}) -> ${JSON.stringify(v)}`);
			const missing = v === void 0 || v === null;
			if (name.startsWith("opt")) {
				if (!missing) return this.jval(v);
				if (shorty(sig).length > 1) return va.next();
				if (name.includes("String")) return this.newHandle({
					kind: "string",
					val: ""
				});
				if (name.includes("Boolean")) return this.newHandle({
					kind: "boolean",
					val: false
				});
				return this.newHandle({
					kind: "long",
					val: 0
				});
			}
			return missing ? 0 : this.jval(v);
		}
		if (o.kind === "long" || o.kind === "boolean") {
			if (name === "intValue" || name === "longValue" || name === "byteValue" || name === "shortValue" || name === "doubleValue" || name === "floatValue" || name === "booleanValue") return this.newHandle({
				kind: "long",
				val: o.val
			});
			return;
		}
	}
	doSyscall(cpu, nr) {
		if (this.opts.cold) {
			this.coldSyscall(cpu, nr);
			return;
		}
		const x0 = Number(cpu.x[0]);
		const x1 = Number(cpu.x[1]);
		const x2 = Number(cpu.x[2]);
		this.svcLog.push(nr);
		switch (nr) {
			case 174:
			case 175:
				cpu.x[0] = 0n;
				return;
			case 172:
			case 173:
			case 178:
			case 96:
				cpu.x[0] = BigInt(this.pid);
				return;
			case 56: {
				const path = this.mem.cstr(x1);
				const fd = this.sysOpen(path);
				if (this.verbose) console.log(`[sys] openat(${JSON.stringify(path)}, 0x${(x2 & 4294967295).toString(16)}) => ${fd}`);
				cpu.x[0] = BigInt.asUintN(32, BigInt(fd));
				return;
			}
			case 48:
			case 34:
			case 79:
				cpu.x[0] = 4294967294n;
				return;
			case 80:
				this.sysFstat(x0 & 4294967295, x1);
				cpu.x[0] = 0n;
				return;
			case 63: {
				const n = this.sysRead(x0 & 4294967295, x1, x2);
				if (this.verbose) console.log(`[sys] read(fd=${x0}, n=${x2}) => ${n}`);
				cpu.x[0] = BigInt.asUintN(32, BigInt(n));
				return;
			}
			case 64:
				if (this.verbose) console.log(`[sys] write(fd=${x0}, n=${x2})`);
				cpu.x[0] = BigInt(x2 & 4294967295);
				return;
			case 57:
				this.fds.delete(x0 & 4294967295);
				cpu.x[0] = 0n;
				return;
			case 113: {
				const [sec, nsec] = x0 === 0 || x0 === 5 ? [this.ts, FROZEN_SUB] : this.monoTime();
				if (x1) {
					this.mem.write(x1, 8, BigInt(sec));
					this.mem.write(x1 + 8, 8, BigInt(nsec));
				}
				cpu.x[0] = 0n;
				return;
			}
			case 169:
				if (x0) {
					this.mem.write(x0, 8, BigInt(this.ts));
					this.mem.write(x0 + 8, 8, BigInt(FROZEN_SUB));
				}
				cpu.x[0] = 0n;
				return;
			case 278: {
				const n = x1 & 4294967295;
				if (x0) this.mem.load(x0, new Uint8Array(n));
				cpu.x[0] = BigInt(n);
				return;
			}
			case 99:
			case 167:
			case 98:
			case 226:
			case 215:
				cpu.x[0] = 0n;
				return;
			case 222:
			case 220:
				cpu.x[0] = 18446744073709551615n;
				return;
			default:
				this.stopReason = `unimplemented syscall nr=${nr} pc=0x${(cpu.pc - 4).toString(16)} lr=0x${Number(cpu.x[30]).toString(16)} x0=0x${x0.toString(16)} x1=0x${x1.toString(16)} x2=0x${x2.toString(16)}`;
				if (this.verbose) console.log("[sys] !! " + this.stopReason);
				throw new Error(this.stopReason);
		}
	}
	sysOpen(path) {
		if (path === "/dev/urandom" || path === "/dev/random") {
			const fd = this.nextFd;
			this.nextFd += 1;
			this.fds.set(fd, {
				kind: "urandom",
				data: null
			});
			return fd;
		}
		return -2;
	}
	sysFstat(fd, buf) {
		if (!buf) return;
		this.mem.load(buf, /* @__PURE__ */ new Uint8Array(128));
		const ent = this.fds.get(fd);
		if (!ent) return;
		const size = ent.kind === "urandom" ? 512 : ent.data ? ent.data.length : 0;
		this.mem.write(buf + 16, 4, BigInt(33188));
		this.mem.write(buf + 20, 4, 1n);
		this.mem.write(buf + 48, 8, BigInt(size));
		this.mem.write(buf + 56, 8, 4096n);
		this.mem.write(buf + 64, 8, BigInt(Math.ceil(size / 512)));
	}
	sysRead(fd, buf, count) {
		const ent = this.fds.get(fd);
		if (!ent) return -9;
		if (ent.kind === "urandom") {
			const n = Math.min(count, 512);
			this.mem.load(buf, new Uint8Array(n));
			return n;
		}
		if (ent.data) {
			const n = Math.min(count, ent.data.length);
			this.mem.load(buf, ent.data.subarray(0, n));
			return n;
		}
		return 0;
	}
	run() {
		if (this.opts.cold) return this.runCold();
		this.load();
		this.patchInitTime();
		this.setRegs();
		this.decodeJniTable();
		this.installHooks();
		const cpu = this.cpu;
		cpu.svc = (c, imm) => this.onSvc(c, imm);
		cpu.tick = this.maxSteps;
		if (this.verbose) console.log(`[run] entry=0x${this.entryPc.toString(16)} sp=0x${this.regs.sp.toString(16)} url_handle=0x${this.urlHandle.toString(16)} url_len=${this.opts.url.length}`);
		this.steps = 0;
		this.pcIndex = 0;
		for (;;) {
			if (cpu.pc === this.retPc) {
				this.donePc = cpu.pc;
				break;
			}
			const idx = this.pcIndex++;
			if (process.env.SO_PROGRESS && idx % 2e4 === 0) console.log(`[p] #${idx} pc=+0x${(cpu.pc - this.base).toString(16)} steps=${this.steps}`);
			if (this.tracePc && idx < this.tracePc) this.pcSeq.push(cpu.pc);
			const h = this.pcHooks.get(cpu.pc);
			if (h && h(cpu)) continue;
			if (this.steps >= this.maxSteps) {
				this.stopReason = `指令预算耗尽 @0x${cpu.pc.toString(16)}`;
				break;
			}
			if (this.stepDump && idx === this.stepDump) {
				const rs = [];
				for (let i = 0; i <= 30; i++) rs.push(`x${i}=0x${cpu.x[i].toString(16)}`);
				console.log(`[step] #${idx} pc=0x${cpu.pc.toString(16)} sp=0x${cpu.x[31].toString(16)} nzcv=${cpu.nzcv}\n[step] ${rs.join(" ")}`);
				this.stopReason = "step dump";
				break;
			}
			if (this.regPc && cpu.pc - this.base === this.regPc) {
				const rs = [];
				for (let i = 0; i <= 30; i++) rs.push(`x${i}=0x${cpu.x[i].toString(16)}`);
				console.log(`[regs] #${this.steps} +0x${this.regPc.toString(16)} nzcv=${cpu.nzcv} sp=0x${cpu.x[31].toString(16)}\n[regs] ${rs.join(" ")}`);
				const b = Number(cpu.x[4]);
				try {
					console.log(`[regs] [x4]=0x${this.mem.read(b, 8).toString(16)} [x4+8]=0x${this.mem.read(b + 8, 8).toString(16)}`);
				} catch {}
				const vs = [];
				for (let i = 0; i < 8; i++) vs.push(`v${i}=${cpu.vhi(i).toString(16).padStart(16, "0")}${cpu.vlo(i).toString(16).padStart(16, "0")}`);
				console.log(`[regs] ${vs.join(" ")}`);
			}
			if (this.trace && cpu.pc - this.base === 1606396) {
				const a = Number(cpu.x[0]);
				console.log(`[probe] x0=0x${a.toString(16)} [x0]=0x${this.mem.fetch(a).toString(16)} [x0+4]=0x${this.mem.fetch(a + 4).toString(16)}`);
			}
			if (this.trace && this.steps < this.trace) {
				const w = this.mem.fetch(cpu.pc);
				console.log(`[t] #${this.steps} +0x${(cpu.pc - this.base).toString(16)} w=${w.toString(16).padStart(8, "0")} x0=0x${cpu.x[0].toString(16)} x1=0x${cpu.x[1].toString(16)} x2=0x${cpu.x[2].toString(16)} x8=0x${cpu.x[8].toString(16)} x15=0x${cpu.x[15].toString(16)} x16=0x${cpu.x[16].toString(16)} x17=0x${cpu.x[17].toString(16)} x29=0x${cpu.x[29].toString(16)} sp=0x${cpu.x[31].toString(16)}`);
			}
			if (this.tailN) {
				let w = 0;
				try {
					w = this.mem.fetch(cpu.pc);
				} catch {
					w = 0;
				}
				this.tailBuf.push(`#${this.steps} +0x${(cpu.pc - this.base).toString(16)} w=${w.toString(16).padStart(8, "0")} x0=0x${cpu.x[0].toString(16)} x1=0x${cpu.x[1].toString(16)} x8=0x${cpu.x[8].toString(16)} x30=0x${cpu.x[30].toString(16)}`);
				if (this.tailBuf.length > this.tailN) this.tailBuf.shift();
			}
			try {
				cpu.step();
			} catch (e) {
				const msg = e.message;
				if (cpu.pc === this.retPc) {
					this.donePc = cpu.pc;
					break;
				}
				this.stopReason = `异常 ${msg} @pc=0x${cpu.pc.toString(16)} lr=0x${Number(cpu.x[30]).toString(16)}`;
				break;
			}
			this.steps += 1;
		}
		if (this.tailN) for (const s of this.tailBuf) console.log(`[tail] ${s}`);
		const retObj = this.obj(Number(cpu.x[0]));
		const headers = {};
		if (retObj && retObj.kind === "objarray") {
			const items = retObj.val;
			for (let i = 0; i + 1 < items.length; i += 2) {
				const k = this.obj(items[i]);
				const v = this.obj(items[i + 1]);
				if (k && k.kind === "string") headers[k.val] = v && v.kind === "string" ? v.val : String(v?.val ?? "");
			}
		}
		return {
			headers,
			stopReason: this.stopReason || (this.donePc !== null ? `normal return to 0x${this.donePc.toString(16)}` : "unknown"),
			steps: this.steps,
			jniCalls: { ...this.jniCount },
			syscalls: [...new Set(this.svcLog)].sort((a, b) => a - b),
			newStrings: this.nstr,
			retObj
		};
	}
	envPtr() {
		return this.opts.cold ? this.coldEnv : this.regs.x0;
	}
	/** 冷加载：系统库 + libmetasec_ml.so，不读 state_a 快照 */
	loadCold() {
		const c = this.opts.cold;
		for (const l of [
			{
				name: "libc.so",
				base: 1079705600
			},
			{
				name: "libdl.so",
				base: 1079574528
			},
			{
				name: "libm.so",
				base: 1080688640
			},
			{
				name: "liblog.so",
				base: 1078394880
			}
		]) this.coldLibs.push({
			name: l.name,
			img: new ElfImage(join(c.libDir, l.name)),
			base: l.base
		});
		this.coldMeta = new ElfImage(c.soPath);
		for (const l of this.coldLibs) for (const [n, v] of l.img.exports) if (!this.coldGlobals.has(n)) this.coldGlobals.set(n, l.base + v);
		for (const [n, v] of this.coldMeta.exports) if (!this.coldGlobals.has(n)) this.coldGlobals.set(n, SO_BASE + v);
		const resolve = (name) => this.coldGlobals.get(name) ?? 0;
		for (const l of this.coldLibs) {
			mapImage(this.mem, l.img, l.base);
			this.segs.push([l.base, l.img.extent]);
		}
		for (const l of this.coldLibs) applyRelocs(this.mem, l.img, l.base, resolve);
		mapImage(this.mem, this.coldMeta, SO_BASE);
		this.segs.push([SO_BASE, this.coldMeta.extent]);
		const st = applyRelocs(this.mem, this.coldMeta, SO_BASE, resolve);
		if (this.verbose) console.log(`[cold] libmetasec extent=0x${this.coldMeta.extent.toString(16)} reloc=${st.applied}/${this.coldMeta.relocs.length} und=${st.unresolved.size}` + (st.unresolved.size ? ` [${[...st.unresolved.keys()].join(",")}]` : ""));
		this.mem.map(3204448256, 16777216);
		this.segs.push([3204448256, 16777216]);
		this.mem.map(this.coldHeap, 67108864);
		this.segs.push([this.coldHeap, 67108864]);
		this.mem.map(1081081856, 83886080);
		this.segs.push([1081081856, 83886080]);
		this.base = SO_BASE;
		this.coldInitArray = readInitArray(this.mem, this.coldMeta, SO_BASE);
		const onload = this.coldMeta.exports.get("JNI_OnLoad") ?? 0;
		this.coldJniOnLoad = onload ? SO_BASE + onload : 0;
		this.mmapNext = Math.max(1090519040, SO_BASE + this.coldMeta.extent);
		this.cpu = new Cpu(this.mem);
		this.cpu.tpidr = BigInt(this.coldSp + 8);
		this.objs.set(this.coldApplication, {
			kind: "object",
			val: "application"
		});
		this.objs.set(this.coldClassHandle, {
			kind: "class",
			val: "com/bytedance/mobsec/metasec/ml/MS"
		});
		this.classes.set(this.coldClassHandle, "com/bytedance/mobsec/metasec/ml/MS");
		this.coldInstallLibHooks();
		if (this.watchSpec) {
			const [lo, len] = this.watchSpec;
			this.mem.watch = {
				lo,
				hi: lo + len,
				cb: (a, s, v) => console.log(`[memwr] #${this.steps} pc=+0x${(this.cpu.pc - this.base).toString(16)} addr=0x${a.toString(16)} size=${s} v=0x${v.toString(16)}`)
			};
		}
		if (process.env.SO_CTXLOG) {
			this.ctxTrace = [];
			this.mem.watch = {
				lo: 3221216512,
				hi: 3221217536,
				cb: (a, _s, v) => {
					const pc = this.cpu.pc - 4 - this.base;
					if (a === 3221216868 && pc === 1616024) {
						this.ctxTrace.push("END");
						this.mem.watch = null;
						return;
					}
					this.ctxTrace.push(`${pc.toString(16)} ${a.toString(16)} ${v.toString(16)}`);
					if (this.ctxTrace.length > 6e3) this.ctxTrace.splice(0, 1e3);
				}
			};
		}
		if (process.env.SO_BBLOG) {
			this.bbActive = false;
			this.bbPrev = -1;
			this.bbBlocks = [];
			this.bbReads = [];
			this.mem.watch = {
				lo: 1085096832,
				hi: 1085097648,
				cb: () => {
					if (this.bbActive) return;
					this.bbActive = true;
					this.mem.watchRead = { cb: (a, s, v) => {
						this.bbReads.push(`${(this.cpu.pc - SO_BASE).toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
					} };
				}
			};
			this.bbWrites = [];
			this.mem.watch2 = {
				lo: 1081864192,
				hi: 1081868288,
				cb: (a, s, v) => {
					this.bbWrites.push(`${(this.cpu.pc - SO_BASE).toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
				}
			};
			const inRegion = (a) => a >= 1081864192 && a < 1081868288;
			const oc = this.mem.copy.bind(this.mem);
			this.mem.copy = (d, s, n) => {
				if (inRegion(d)) this.bbWrites.push(`copy dst=0x${d.toString(16)} src=0x${s.toString(16)} n=${n} lr=+0x${(Number(this.cpu.x[30]) - SO_BASE).toString(16)} data=${Buffer.from(this.mem.slice(s, Math.min(n, 40))).toString("hex")}`);
				oc(d, s, n);
			};
			const of = this.mem.fill.bind(this.mem);
			this.mem.fill = (d, v, n) => {
				if (inRegion(d)) this.bbWrites.push(`fill dst=0x${d.toString(16)} v=${v} n=${n}`);
				of(d, v, n);
			};
			const ol = this.mem.load.bind(this.mem);
			this.mem.load = (d, b) => {
				if (inRegion(d)) this.bbWrites.push(`load dst=0x${d.toString(16)} n=${b.length}`);
				ol(d, b);
			};
		}
		if (process.env.SO_VM1DUMP) {
			let vm1Done = false;
			this.mem.watch = {
				lo: 1085096832,
				hi: 1085097571,
				cb: (a) => {
					if (vm1Done || a !== 1085096832) return;
					const pc = this.cpu.pc - 4 - SO_BASE;
					if (pc !== 1618516) return;
					vm1Done = true;
					const regs = [];
					for (let r = 0; r <= 28; r++) regs.push(`x${r}=${this.cpu.x[r].toString(16)}`);
					regs.push(`lr=${this.cpu.x[30].toString(16)}`);
					writeFileSync("d:/there/douyinhook/unidbg_work/vm1in_ts.txt", ["TS", `pc=${pc.toString(16)} sp=${this.cpu.x[31].toString(16)}`].concat(regs).join("\n") + "\nstack_bfffa000=" + Buffer.from(this.mem.slice(3221200896, 18432)).toString("hex") + "\nheap_40780000=" + Buffer.from(this.mem.slice(1081606144, 20480)).toString("hex") + "\nad_40ad0000=" + Buffer.from(this.mem.slice(1085079552, 18432)).toString("hex") + "\n");
					this.mem.watch = null;
				}
			};
		}
		if (process.env.SO_RFLOG) {
			const rfGate = process.env.SO_RFGATE ? Number.parseInt(process.env.SO_RFGATE, 16) : 1081865471;
			this.rfLog = [];
			this.mem.watch = {
				lo: 3221212072,
				hi: 3221216168,
				cb: (a, s, v) => {
					if (!this.rfOn || this.rfLog.length >= 2e6) return;
					this.rfLog.push(`${(this.cpu.pc - 4 - SO_BASE).toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
				}
			};
			this.mem.watch2 = {
				lo: 1081865216,
				hi: 1081866011,
				cb: (a, s, v) => {
					if (a === 1081865471) this.rfOn = true;
					if (!this.rfOn || this.rfLog.length >= 2e6) return;
					this.rfLog.push(`S ${a.toString(16)} ${s} ${v.toString(16)}`);
				}
			};
			if (rfGate !== 1081865471) this.mem.watch3 = {
				lo: rfGate,
				hi: rfGate + 1,
				cb: () => {
					this.rfOn = true;
				}
			};
		}
		if (process.env.SO_WLOG) {
			const [ls, hs] = process.env.SO_WLOG.split("-");
			const lo = Number.parseInt(ls, 16);
			const hi = Number.parseInt(hs, 16);
			this.wlog = [];
			this.mem.watch = {
				lo,
				hi,
				cb: (a, s, v) => {
					if (this.wlog.length < 4e5) {
						const pc = this.cpu.pc - 4 - SO_BASE;
						let extra = "";
						if (pc === 1618516) extra = ` r=${this.cpu.x[17]} b=${this.cpu.x[4]} i=${this.cpu.x[16]} v14=${this.cpu.x[14]}`;
						this.wlog.push(`W ${pc.toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}${extra}`);
					}
				}
			};
		}
		if (process.env.SO_WATCHADDR) {
			const lo = Number.parseInt(process.env.SO_WATCHADDR, 16);
			this.ctxTrace = [];
			this.mem.watch = {
				lo,
				hi: lo + 32,
				cb: (a, s, v) => {
					const pc = this.cpu.pc - 4 - this.base;
					this.ctxTrace.push(`${pc.toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
					if (this.ctxTrace.length > 2e4) this.ctxTrace.splice(0, 2e3);
				}
			};
		}
		if (process.env.SO_FRAMELOG) {
			const lo = Number.parseInt(process.env.SO_FRAMELOG, 16);
			this.ctxTrace = [];
			this.mem.watch = {
				lo,
				hi: lo + 4096,
				cb: (a, s, v) => {
					const pc = this.cpu.pc - 4 - this.base;
					this.ctxTrace.push(`${pc.toString(16)} ${a.toString(16)} ${s} ${v.toString(16)}`);
				}
			};
		}
	}
	/** 自建 JNIEnv / JavaVM：每个槽都是 `svc #(0x100+i); ret` 桩 */
	coldBuildJni() {
		const region = 4294770688;
		const stubBase = 4294836224;
		const envTbl = 4294841344;
		const vmTbl = 4294843904;
		this.mem.map(region, 131072);
		this.segs.push([region, 131072]);
		const putStub = (p, imm) => {
			this.mem.write(p, 4, BigInt((3556769793 | (imm & 65535) << 5) >>> 0));
			this.mem.write(p + 4, 4, 3596551104n);
		};
		for (let i = 0; i < 260; i++) {
			const p = stubBase + i * 16;
			putStub(p, 256 + i);
			this.mem.write(envTbl + i * 8, 8, BigInt(p));
			this.imm2jni.set(256 + i, i);
		}
		for (let i = 0; i < 8; i++) {
			const p = stubBase + (260 + i) * 16;
			putStub(p, 768 + i);
			this.mem.write(vmTbl + i * 8, 8, BigInt(p));
			this.imm2jni.set(768 + i, 1e3 + i);
		}
		this.mem.write(this.coldEnv, 8, BigInt(envTbl));
		this.mem.write(this.coldVm, 8, BigInt(vmTbl));
	}
	/** 最近 512 条指令 pc（按时间顺序） */
	coldTailText() {
		const t = this.coldTail;
		const out = [];
		for (let i = 0; i < 512; i++) out.push(t[this.coldTailIdx + i & 511].toString(16));
		return out.join(" ");
	}
	/** 在冷启动的干净栈上调用一个 so 函数（返回 x0） */
	coldCall(entry, args, budget = this.maxSteps) {
		const cpu = this.cpu;
		for (let i = 0; i <= 30; i++) cpu.x[i] = 0n;
		for (let i = 0; i < args.length && i < 8; i++) cpu.x[i] = BigInt.asUintN(64, BigInt(args[i]));
		cpu.x[30] = BigInt(this.coldSentinel);
		cpu.x[31] = BigInt(this.coldSp);
		cpu.pc = entry;
		cpu.tick = budget;
		this.steps = 0;
		this.coldTailIdx = 0;
		const rwSpec = process.env.SO_REGWATCH;
		const rwTargets = rwSpec ? new Set(rwSpec.split(",").map((s) => s.toLowerCase())) : void 0;
		const rwPrev = [
			0n,
			0n,
			0n,
			0n,
			0n,
			0n
		];
		if (rwTargets) for (let r = 1; r <= 5; r++) rwPrev[r] = cpu.x[r];
		const hitSpec = process.env.SO_PCHIT;
		const hitSet = hitSpec ? new Set(hitSpec.split(",").map((s) => SO_BASE + Number.parseInt(s, 16))) : void 0;
		const srcPc = process.env.SO_SRCPC ? SO_BASE + Number.parseInt(process.env.SO_SRCPC, 16) : 0;
		const hexPc = process.env.SO_HEXLOG ? SO_BASE + Number.parseInt(process.env.SO_HEXLOG, 16) : 0;
		const dbgLdrb = !!process.env.SO_LDRBLOG;
		const dbgB64 = !!process.env.SO_B64LOG;
		const dbgDumpSrc = !!process.env.SO_DUMPSRC;
		const dbgBb = !!process.env.SO_BBLOG;
		const dbgTramp = !!process.env.SO_TRAMPLOG;
		const dbgVmDump = !!process.env.SO_VMDUMP;
		const dbgVmSlot = !!process.env.SO_VMSLOT;
		const dbgVmLoad = !!process.env.SO_VMLOAD;
		const dbgLadon = !!process.env.SO_LADON;
		const verbose = this.verbose;
		if (!dbgLdrb && !dbgB64 && !dbgDumpSrc && !dbgBb && !dbgTramp && !dbgVmDump && !dbgVmSlot && !dbgVmLoad && !dbgLadon && !hitSet && !hexPc && !srcPc && !rwTargets && !verbose) return this.coldCallJit(entry, args, budget);
		for (;;) {
			if (cpu.pc === this.coldSentinel) break;
			const h = this.pcHooks.get(cpu.pc);
			if (h && h(cpu)) continue;
			if (hitSet && hitSet.has(cpu.pc)) {
				const regs = [];
				for (let r = 0; r <= 17; r++) regs.push(`${r}:${cpu.x[r].toString(16)}`);
				writeFileSync("d:/there/douyinhook/unidbg_work/pchit.txt", `pc=+0x${(cpu.pc - SO_BASE).toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} sp=0x${cpu.x[31].toString(16)} ${regs.join(" ")}\n`, { flag: "a" });
			}
			if (hexPc && cpu.pc === hexPc) {
				const n = Number(cpu.x[1]);
				const p = Number(cpu.x[0]);
				writeFileSync("d:/there/douyinhook/unidbg_work/hexlog.txt", `len=${n} src=0x${p.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} ${Buffer.from(this.mem.slice(p, Math.min(n, 64))).toString("hex")}\n`, { flag: "a" });
			}
			if (dbgLdrb && cpu.pc === 1075354264) {
				const a = Number(cpu.x[16]) + Number(cpu.x[17]);
				this.ldrbLog.push(`${a.toString(16)} ${Number(this.mem.read(a, 1)).toString(16)}`);
			}
			if (dbgB64 && cpu.pc === 1076298484) {
				const len = Number(cpu.x[4]) & 4294967295;
				const src = Number(cpu.x[3]);
				const lo = src - 64;
				writeFileSync("d:/there/douyinhook/unidbg_work/b64log.txt", `len=${len} src=0x${src.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} @0x${lo.toString(16)}\n${Buffer.from(this.mem.slice(lo, 128)).toString("hex")}\n`, { flag: "a" });
			}
			if (dbgDumpSrc && cpu.pc === 1076589556 && Number(cpu.x[0]) === 1085098624) {
				writeFileSync("d:/there/douyinhook/unidbg_work/body_src_ts.bin", this.mem.slice(1085096823, 812));
				process.env.SO_DUMPSRC = "";
			}
			if (dbgBb && this.bbActive) {
				if (cpu.pc === 1076589556) {
					const a0 = Number(cpu.x[0]);
					if (a0 >= 1085097984 && a0 < 1085100288) {
						writeFileSync("d:/there/douyinhook/unidbg_work/bb_ts.txt", this.bbBlocks.map((p) => p.toString(16)).join("\n") + "\n");
						writeFileSync("d:/there/douyinhook/unidbg_work/bb_reads_ts.txt", this.bbReads.join("\n") + "\n");
						writeFileSync("d:/there/douyinhook/unidbg_work/bb_wr_ts.txt", this.bbWrites.join("\n") + "\n");
						this.bbActive = false;
						this.mem.watch = null;
						this.mem.watchRead = null;
					}
				}
				if (this.bbActive) {
					if (cpu.pc !== this.bbPrev + 4 && cpu.pc >= 1073741824 && cpu.pc < 1077704720) this.bbBlocks.push(cpu.pc - SO_BASE);
					this.bbPrev = cpu.pc;
				}
			}
			if (dbgTramp && cpu.pc === 1076589556) {
				const fn = Number(cpu.x[8]);
				const a0 = Number(cpu.x[0]);
				const a1 = Number(cpu.x[1]);
				const a2 = Number(cpu.x[2]);
				if (a0 >= 1085097984 && a0 < 1085100288) {
					let src = "";
					try {
						src = Buffer.from(this.mem.slice(a1, Math.min(a2, 96))).toString("hex");
					} catch {
						src = "<err>";
					}
					writeFileSync("d:/there/douyinhook/unidbg_work/tramp_ts.txt", `T fn=+0x${(fn - SO_BASE).toString(16)} a0=0x${a0.toString(16)} a1=0x${a1.toString(16)} a2=${a2} obj=0x${Number(cpu.x[19]).toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} src=${src}\n`, { flag: "a" });
				}
			}
			if (dbgVmDump && cpu.pc === 1075357852) {
				const x1 = Number(cpu.x[1]);
				const x4 = Number(cpu.x[4]);
				let off = Number(cpu.x[16]) & 4294967295;
				if (off & 2147483648) off -= 4294967296;
				if (x1 + off === 3221216868) {
					const lines = [`pc=+0x18a898 x4=0x${x4.toString(16)} x1=0x${x1.toString(16)} off=${off} w15=0x${(Number(cpu.x[15]) & 4294967295).toString(16)}`];
					for (let i = 0; i < 96; i += 8) lines.push(`  ctx+0x${i.toString(16)} = ${Buffer.from(this.mem.slice(x4 + i, 8)).toString("hex")}`);
					writeFileSync("d:/there/douyinhook/unidbg_work/vmdump.txt", lines.join("\n") + "\n", { flag: "a" });
				}
			}
			if (dbgVmSlot && cpu.pc === 1075323620) {
				const x4 = Number(cpu.x[4]);
				const w10 = Number(cpu.x[10]) & 4294967295;
				const dst = w10 >>> 17 & 31;
				if (dst === 3) {
					const src = w10 >>> 27 & 31;
					const sh = w10 >>> 22 & 31;
					const sv = Number(this.mem.read(x4 + src * 8, 4)) >>> 0;
					writeFileSync("d:/there/douyinhook/unidbg_work/vmslot.txt", `w10=0x${w10.toString(16)} dst=${dst} src=${src} sh=${sh} slot=${sv.toString(16)} ctx=0x${x4.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}\n`, { flag: "a" });
				}
			}
			if (dbgVmLoad && cpu.pc === 1075353808) {
				const x1 = Number(cpu.x[1]) & 4294967295;
				if (x1 === 2) {
					const x4 = Number(cpu.x[4]);
					const base = Number(cpu.x[17]);
					const off = Number(cpu.x[0]) & 4294967295;
					let v = 0;
					try {
						v = Number(this.mem.read(base + off >>> 0, 4)) >>> 0;
					} catch {
						v = 57005;
					}
					writeFileSync("d:/there/douyinhook/unidbg_work/vmload.txt", `slot=${x1} base=0x${base.toString(16)} off=0x${off.toString(16)} val=0x${v.toString(16)} ctx=0x${x4.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}\n`, { flag: "a" });
				}
			}
			if (dbgLadon) {
				if (cpu.pc === 1076322224) {
					const a0 = Number(cpu.x[0]);
					const a1 = Number(cpu.x[1]) & 4294967295;
					let dat = "";
					try {
						dat = Buffer.from(this.mem.slice(a0, Math.min(a1, 32))).toString("hex");
					} catch {
						dat = "<err>";
					}
					writeFileSync("d:/there/douyinhook/unidbg_work/ladon_ts.txt", `FN275FAC a0=0x${a0.toString(16)} a1=${a1} data=${dat} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}\n`, { flag: "a" });
				}
				if (cpu.pc === 1075351e3) {
					const x16 = Number(cpu.x[16]);
					const w21 = Number(cpu.x[21]) & 65535;
					const off = w21 & 32768 ? w21 - 65536 : w21;
					const addr = x16 + off >>> 0;
					let v = 0n;
					try {
						v = this.mem.read(addr, 8);
					} catch {
						v = 0n;
					}
					if (v >> 32n === 2470774779n) writeFileSync("d:/there/douyinhook/unidbg_work/ladon_ts.txt", `LD188 addr=0x${addr.toString(16)} v=0x${v.toString(16)} x16=0x${x16.toString(16)} off=0x${off.toString(16)}\n`, { flag: "a" });
				}
				if (cpu.pc === 1076378332) {
					const buf = Number(cpu.x[0]);
					const len = Number(cpu.x[1]) & 4294967295;
					let data = "";
					try {
						data = Buffer.from(this.mem.slice(buf, Math.min(len, 96))).toString("hex");
					} catch {
						data = "<err>";
					}
					writeFileSync("d:/there/douyinhook/unidbg_work/ladon_ts.txt", `HASH buf=0x${buf.toString(16)} len=${len} data=${data}\n`, { flag: "a" });
				}
				if (cpu.pc === 1075330776) {
					const x4 = Number(cpu.x[4]);
					const w10 = Number(cpu.x[10]) & 4294967295;
					if (w10 >>> 27 === 1) {
						const s1 = w10 >>> 12 & 31;
						const s2 = w10 >>> 17 & 31;
						const v1 = this.mem.read(x4 + s1 * 8, 8).toString(16);
						const v2 = this.mem.read(x4 + s2 * 8, 8).toString(16);
						let mem = "";
						const p2 = Number(this.mem.read(x4 + s2 * 8, 8) & 4294967295n);
						if (p2 >= 1073741824 && p2 < 1107296256) try {
							mem = ` mem=${Buffer.from(this.mem.slice(p2, 48)).toString("hex")}`;
						} catch {
							mem = " mem=<err>";
						}
						writeFileSync("d:/there/douyinhook/unidbg_work/ladon_ts.txt", `XOR w10=0x${w10.toString(16)} s1=${s1}(0x${v1}) s2=${s2}(0x${v2}) ctx=0x${x4.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)}${mem}\n`, { flag: "a" });
					}
				}
			}
			if (srcPc && cpu.pc === srcPc) {
				const n = Number(cpu.x[11]) & 4294967295;
				if (n >= 32) {
					const p = Number(cpu.x[23]);
					writeFileSync("d:/there/douyinhook/unidbg_work/srclog.txt", `len=${n} x23=0x${p.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} \t${this.mem.cstr(p).slice(0, 60)}\n`, { flag: "a" });
				}
			}
			if (this.steps >= budget) throw new Error(`冷启动指令预算耗尽 @0x${cpu.pc.toString(16)}\n  最近指令: ${this.coldTailText()}`);
			this.coldTail[this.coldTailIdx] = cpu.pc;
			this.coldTailIdx = this.coldTailIdx + 1 & 511;
			if (verbose) {
				const inLibc = cpu.pc >= 1079705600 && cpu.pc < 1080819712;
				if (inLibc !== this.coldInLibc) {
					console.log(`[cold] ${inLibc ? "进入" : "离开"} libc @0x${cpu.pc.toString(16)} lr=0x${Number(cpu.x[30]).toString(16)}`);
					this.coldInLibc = inLibc;
				}
			}
			try {
				cpu.step();
			} catch (e) {
				throw new Error(`冷启动异常 ${e.message} @pc=0x${cpu.pc.toString(16)} lr=0x${Number(cpu.x[30]).toString(16)} x0=0x${cpu.x[0].toString(16)}\n  x8=0x${cpu.x[8].toString(16)} x19=0x${cpu.x[19].toString(16)} x20=0x${cpu.x[20].toString(16)} x21=0x${cpu.x[21].toString(16)} sp=0x${cpu.x[31].toString(16)}\n  最近指令: ${this.coldTailText()}`);
			}
			this.steps += 1;
			if (rwTargets) for (let r = 1; r <= 5; r++) {
				const v = cpu.x[r];
				if (v !== rwPrev[r]) {
					rwPrev[r] = v;
					if (rwTargets.has(v.toString(16))) writeFileSync("d:/there/douyinhook/unidbg_work/regwatch.txt", `pc=+0x${(cpu.pc - 4 - SO_BASE).toString(16)} x${r} <= 0x${v.toString(16)} lr=+0x${(Number(cpu.x[30]) - SO_BASE).toString(16)} sp=0x${cpu.x[31].toString(16)}\n`, { flag: "a" });
				}
			}
		}
		return Number(cpu.x[0]);
	}
	/**
	* JIT 版 coldCall：按基本块翻译执行，语义与 coldCall 一致。
	* 仅在没有任何调试开关时走这里（调试路径仍用逐条解释，方便 dump）。
	*/
	coldCallJit(entry, args, budget) {
		const cpu = this.cpu;
		const xlo = cpu.xlo;
		const xhi = cpu.xhi;
		for (let i = 0; i <= 30; i++) {
			xlo[i] = 0;
			xhi[i] = 0;
		}
		for (let i = 0; i < args.length && i < 8; i++) {
			const v = args[i];
			xlo[i] = v | 0;
			xhi[i] = Math.floor(v / 4294967296) | 0;
		}
		xlo[30] = this.coldSentinel | 0;
		xhi[30] = 0;
		xlo[31] = this.coldSp | 0;
		xhi[31] = Math.floor(this.coldSp / 4294967296) | 0;
		cpu.pc = entry;
		cpu.tick = budget;
		this.steps = 0;
		this.coldTailIdx = 0;
		if (this.jit === null || this.jitHooks !== this.pcHooks.size) {
			const sk = process.env.SO_JITSKIP;
			const skip = sk ? new Set(sk.split(",").map((s) => Number(s.trim())).filter((n) => n > 0)) : void 0;
			this.jit = new Jit(cpu, this.mem, this.coldSentinel, this.pcHooks, skip, SO_BASE, SO_BASE + this.coldMeta.extent);
			this.jitHooks = this.pcHooks.size;
		}
		const jit = this.jit;
		const IDX = jit.idx;
		const LIST = jit.list;
		const HP = jit.hookPages;
		const LO = jit.codeLo;
		const SPAN = jit.codeHi - jit.codeLo;
		const hooks = this.pcHooks;
		const THRESH = this.jitThresh;
		let steps = 0;
		for (;;) {
			const pc = cpu.pc;
			if (pc === this.coldSentinel) break;
			const off = pc - LO;
			const inCode = off >>> 0 < SPAN;
			if (!inCode || HP[off >>> 16] !== 0) {
				const h = hooks.get(pc);
				if (h !== void 0 && h(cpu)) continue;
			}
			if (steps >= budget) {
				this.steps = steps;
				throw new Error(`冷启动指令预算耗尽 @0x${pc.toString(16)}`);
			}
			let b = inCode ? LIST[IDX[off >>> 2] - 1] : jit.slowBlocks.get(pc);
			if (b === void 0) {
				if (inCode) {
					const k = off >>> 2;
					const v = IDX[k];
					if (v === 0) {
						IDX[k] = -1;
						cpu.step();
						steps += 1;
						continue;
					}
					if (v > -THRESH) {
						IDX[k] = v - 1;
						cpu.step();
						steps += 1;
						continue;
					}
				}
				b = jit.compile(pc);
			}
			if (b.n === 0) {
				cpu.step();
				steps += 1;
				continue;
			}
			if (Jit.STAT) b.c = (b.c ?? 0) + 1;
			b.f(cpu);
			steps += b.n;
		}
		this.steps = steps;
		if (process.env.SO_JITSTAT) {
			let ins = 0;
			for (const x of LIST) ins += x.n;
			console.log(`[jit] blocks=${LIST.length} avg=${(ins / LIST.length).toFixed(1)} steps=${steps}`);
			for (const x of [...LIST].sort((a, b) => (b.c ?? 0) - (a.c ?? 0)).slice(0, 2)) console.log(`--- calls=${x.c} n=${x.n}\n${(x.src ?? "").slice(0, 1500)}`);
		}
		return xlo[0] >>> 0 === 0 && xhi[0] === 0 ? 0 : Number(cpu.x[0]);
	}
	/** 按 Java 侧 k3.callStaticJniMethodObject 的约定调用 native b */
	coldB(op, a2, a3, a4, a5) {
		if (op === 33554438) this.loadReplay();
		if (process.env.SO_MALLLOG && op === 33554438) writeFileSync("d:/there/douyinhook/unidbg_work/malllog.txt", "MARK sign\n", { flag: "a" });
		const r = this.coldCall(this.coldEntry, [
			this.coldEnv,
			this.coldClassHandle,
			op,
			a2,
			a3,
			a4,
			a5
		]);
		if (process.env.SO_STEPLOG) console.log(`[b] op=${op} steps=${this.steps} ret=0x${r.toString(16)}`);
		return r;
	}
	/** 指针是否指向合法的 JNINativeMethod 数组（首项的 name 指针可读且像标识符） */
	methodsAt(ptr) {
		try {
			const name = this.mem.cstr(Number(this.mem.read(ptr, 8)));
			return name.length > 0 && /^[A-Za-z_$]/.test(name);
		} catch {
			return false;
		}
	}
	coldRegisterNatives(methods, count) {
		const n = count & 4294967295;
		for (let i = 0; i < n; i++) {
			const p = methods + i * 24;
			const name = this.mem.cstr(Number(this.mem.read(p, 8)));
			const sig = this.mem.cstr(Number(this.mem.read(p + 8, 8)));
			const fn = Number(this.mem.read(p + 16, 8));
			this.coldNative.set(name, fn);
			if (this.verbose) console.log(`[native] ${name}${sig} @0x${fn.toString(16)}`);
		}
	}
	/**
	* 冷启动不能执行真实 libc：bionic 的 dlmalloc / mem* 里用了 SIMD
	* （add v3.2d, v3.2d, v6.2d 之类），解释器不支持，也没必要支持。
	* 这里按导出符号地址打 pc 钩子，用 TS 等价实现。
	*/
	coldInstallLibHooks() {
		const hook = (name, fn) => {
			const addr = this.coldGlobals.get(name);
			if (process.env.SO_SYMLOG) writeFileSync("d:/there/douyinhook/unidbg_work/symlog.txt", `${name} 0x${(addr ?? 0).toString(16)}\n`, { flag: "a" });
			if (addr) this.pcHooks.set(addr, (cpu) => {
				fn(cpu);
				return true;
			});
		};
		const A = (cpu, i) => Number(cpu.x[i]);
		const ret = (cpu, v) => {
			cpu.x[0] = BigInt.asUintN(64, BigInt(v));
			cpu.pc = Number(cpu.x[30]);
		};
		const ret32 = (cpu, v) => ret(cpu, BigInt.asUintN(32, BigInt(v)));
		const rd = (p, n) => Number(this.mem.read(p, n));
		const wr = (p, n, v) => this.mem.write(p, n, BigInt.asUintN(n * 8, BigInt(v)));
		const cstr = (p) => p ? this.mem.cstr(p) : "";
		const slen = (p) => {
			let n = 0;
			while (Number(this.mem.read(p + n, 1)) !== 0) n += 1;
			return n;
		};
		const scmp = (a, b, max) => {
			for (let i = 0; i < max; i++) {
				const x = Number(this.mem.read(a + i, 1));
				const y = Number(this.mem.read(b + i, 1));
				if (x !== y) return x - y;
				if (x === 0) return 0;
			}
			return 0;
		};
		const writeStr = (dst, s, cap) => {
			const b = Buffer.from(s, "utf8");
			if (process.env.SO_FMTADDR && b.length >= 40) writeFileSync("d:/there/douyinhook/unidbg_work/fmtaddr.txt", `dst=0x${dst.toString(16)} cap=${cap} len=${b.length}\t${s.slice(0, 60)}\n`, { flag: "a" });
			if (cap > 0) {
				const n = Math.min(b.length, cap - 1);
				if (n > 0) this.mem.load(dst, b.subarray(0, n));
				this.mem.write(dst + n, 1, 0n);
			}
			return b.length;
		};
		const dMallLog = !!process.env.SO_MALLLOG;
		const mallLog = (name, n, p) => {
			if (!dMallLog) return;
			let extra = "";
			if (n === 48) {
				const sp = Number(this.cpu.x[31]);
				try {
					extra = ` caller=0x${Number(this.mem.read(sp + 8, 8)).toString(16)}`;
				} catch {
					extra = " caller=<err>";
				}
			}
			writeFileSync("d:/there/douyinhook/unidbg_work/malllog.txt", `${name} n=${n} ret=0x${p.toString(16)} lr=0x${Number(this.cpu.x[30]).toString(16)}${extra}\n`, { flag: "a" });
		};
		hook("malloc", (cpu) => {
			const n = A(cpu, 0) || 1;
			const p = this.replayOn && this.replayAlloc("malloc", n) || this.coldAlloc(n);
			mallLog("malloc", n, p);
			ret(cpu, p);
		});
		hook("calloc", (cpu) => {
			const n = A(cpu, 0) * A(cpu, 1) || 1;
			const p = this.replayOn && this.replayAlloc("calloc", n) || this.coldAlloc(n);
			mallLog("calloc", n, p);
			ret(cpu, p);
		});
		hook("realloc", (cpu) => {
			const p = A(cpu, 0);
			const n = A(cpu, 1);
			if (!p) {
				ret(cpu, this.coldAlloc(n || 1));
				return;
			}
			if (!n) {
				this.coldAllocs.delete(p);
				ret(cpu, 0);
				return;
			}
			const oldSize = this.coldAllocs.get(p) ?? 0;
			const q = this.replayOn && this.replayAlloc("realloc", n) || this.coldAlloc(n);
			const k = Math.min(oldSize, n);
			if (k > 0 && q !== p) this.mem.copy(q, p, k);
			if (q !== p) this.coldAllocs.delete(p);
			this.coldAllocs.set(q, n);
			ret(cpu, q);
		});
		hook("free", (cpu) => {
			this.coldAllocs.delete(A(cpu, 0));
			ret(cpu, 0);
		});
		hook("posix_memalign", (cpu) => {
			const pp = A(cpu, 0);
			const align = A(cpu, 1);
			const n = A(cpu, 2);
			let q = this.coldAlloc(n);
			if (align > 16) q = q + align - 1 & ~(align - 1);
			this.coldAllocs.set(q, n);
			wr(pp, 8, q);
			ret32(cpu, 0);
		});
		const dMemLog = !!process.env.SO_MEMLOG;
		const dFrameLog = !!process.env.SO_FRAMELOG;
		const dLdrbLog = !!process.env.SO_LDRBLOG;
		const dRfLog = !!process.env.SO_RFLOG;
		const dWLog = !!process.env.SO_WLOG;
		const dS2Dump = !!process.env.SO_S2DUMP;
		const dDumpCp = process.env.SO_DUMPCP ? Number.parseInt(process.env.SO_DUMPCP, 16) : -1;
		const doMemcpy = (cpu) => {
			const dst = A(cpu, 0);
			const n = A(cpu, 2);
			if (dMemLog && n >= 16 && dst >= 1342177280 && dst < 1343225856) {
				const src = A(cpu, 1);
				writeFileSync("d:/there/douyinhook/unidbg_work/memlog.txt", `dst=0x${dst.toString(16)} src=0x${src.toString(16)} n=${n} lr=+0x${(Number(cpu.x[30]) - this.base).toString(16)} src=${Buffer.from(this.mem.slice(src, Math.min(n, 32))).toString("hex")}\n`, { flag: "a" });
			}
			if (dFrameLog && dst === 1081864299) {
				writeFileSync("d:/there/douyinhook/unidbg_work/frame_ts.txt", this.ctxTrace.join("\n") + "\n");
				this.mem.watch = null;
				process.env.SO_FRAMELOG = "";
			}
			if (dLdrbLog && dst === 1081864299) {
				writeFileSync("d:/there/douyinhook/unidbg_work/ldrb_ts.txt", this.ldrbLog.join("\n") + "\n");
				process.env.SO_LDRBLOG = "";
			}
			if (dRfLog && dst === 1081867264) {
				writeFileSync("d:/there/douyinhook/unidbg_work/rf2_ts.txt", this.rfLog.join("\n") + "\n");
				this.mem.watch = null;
				this.mem.watch2 = null;
				this.mem.watch3 = null;
				process.env.SO_RFLOG = "";
			}
			if (dWLog) {
				const src = A(cpu, 1);
				this.wlog.push(`C ${(Number(cpu.x[30]) - SO_BASE).toString(16)} ${dst.toString(16)} ${src.toString(16)} ${n} ${Buffer.from(this.mem.slice(src, n)).toString("hex")}`);
			}
			if (dS2Dump && dst === 1081867264) {
				writeFileSync("d:/there/douyinhook/unidbg_work/s2_ts.txt", Buffer.from(this.mem.slice(1081866240, 804)).toString("hex") + "\n");
				if (dWLog) writeFileSync("d:/there/douyinhook/unidbg_work/wlog_ts.txt", this.wlog.join("\n") + "\n");
				process.env.SO_S2DUMP = "";
			}
			if (dDumpCp >= 0) {
				const dstWant = dDumpCp;
				if (dst === dstWant) {
					const src = A(cpu, 1);
					writeFileSync(`d:/there/douyinhook/unidbg_work/cp_ts_${dstWant.toString(16)}.txt`, Buffer.from(this.mem.slice(src, n)).toString("hex") + "\n");
				}
			}
			if (n > 0) this.mem.copy(dst, A(cpu, 1), n);
			if (process.env.SO_BBLOG && dst >= 1081864192 && dst < 1081868288) {
				const src = A(cpu, 1);
				this.bbWrites.push(`memcpy dst=0x${dst.toString(16)} src=0x${src.toString(16)} n=${n} lr=+0x${(Number(cpu.x[30]) - this.base).toString(16)} data=${Buffer.from(this.mem.slice(src, Math.min(n, 40))).toString("hex")}`);
			}
			ret(cpu, dst);
		};
		for (const n of [
			"memcpy",
			"__memcpy_chk",
			"memmove",
			"__memmove_chk"
		]) hook(n, doMemcpy);
		const doMemset = (cpu) => {
			const dst = A(cpu, 0);
			const n = A(cpu, 2);
			if (dWLog) this.wlog.push(`F ${(Number(cpu.x[30]) - SO_BASE).toString(16)} ${dst.toString(16)} ${A(cpu, 1).toString(16)} ${n}`);
			if (n > 0) this.mem.fill(dst, A(cpu, 1), n);
			ret(cpu, dst);
		};
		for (const n of ["memset", "__memset_chk"]) hook(n, doMemset);
		hook("memcmp", (cpu) => {
			const a = A(cpu, 0);
			const b = A(cpu, 1);
			const n = A(cpu, 2);
			let r = 0;
			for (let i = 0; i < n; i++) {
				const x = Number(this.mem.read(a + i, 1));
				const y = Number(this.mem.read(b + i, 1));
				if (x !== y) {
					r = x - y;
					break;
				}
			}
			ret32(cpu, r);
		});
		hook("memchr", (cpu) => {
			const p = A(cpu, 0);
			const c = A(cpu, 1) & 255;
			const n = A(cpu, 2);
			let r = 0;
			for (let i = 0; i < n; i++) if (Number(this.mem.read(p + i, 1)) === c) {
				r = p + i;
				break;
			}
			ret(cpu, r);
		});
		for (const n of ["strlen", "__strlen_chk"]) hook(n, (cpu) => ret(cpu, slen(A(cpu, 0))));
		hook("strcmp", (cpu) => ret32(cpu, scmp(A(cpu, 0), A(cpu, 1), Infinity)));
		hook("strncmp", (cpu) => ret32(cpu, scmp(A(cpu, 0), A(cpu, 1), A(cpu, 2))));
		hook("strcpy", (cpu) => {
			const dst = A(cpu, 0);
			this.mem.copy(dst, A(cpu, 1), slen(A(cpu, 1)) + 1);
			ret(cpu, dst);
		});
		hook("strncpy", (cpu) => {
			const dst = A(cpu, 0);
			const src = A(cpu, 1);
			const n = A(cpu, 2);
			let i = 0;
			for (; i < n; i++) {
				const c = Number(this.mem.read(src + i, 1));
				this.mem.write(dst + i, 1, BigInt(c));
				if (c === 0) break;
			}
			for (i += 1; i < n; i++) this.mem.write(dst + i, 1, 0n);
			ret(cpu, dst);
		});
		const doStrdup = (cpu, max) => {
			const src = A(cpu, 0);
			const n = Math.min(slen(src), max);
			const q = this.coldAlloc(n + 1);
			if (n > 0) this.mem.copy(q, src, n);
			this.mem.write(q + n, 1, 0n);
			ret(cpu, q);
		};
		hook("strdup", (cpu) => doStrdup(cpu, Infinity));
		hook("strndup", (cpu) => doStrdup(cpu, A(cpu, 1)));
		hook("strstr", (cpu) => {
			const p = A(cpu, 0);
			const h = cstr(p);
			const i = h.indexOf(cstr(A(cpu, 1)));
			ret(cpu, i < 0 ? 0 : p + Buffer.byteLength(h.slice(0, i)));
		});
		hook("strcasestr", (cpu) => {
			const p = A(cpu, 0);
			const h = cstr(p).toLowerCase();
			const i = h.indexOf(cstr(A(cpu, 1)).toLowerCase());
			ret(cpu, i < 0 ? 0 : p + Buffer.byteLength(h.slice(0, i)));
		});
		hook("strrchr", (cpu) => {
			const p = A(cpu, 0);
			const c = A(cpu, 1) & 255;
			let last = 0;
			for (let i = 0;; i++) {
				const b = Number(this.mem.read(p + i, 1));
				if (b === c) last = p + i;
				if (b === 0) break;
			}
			ret(cpu, last);
		});
		hook("strcspn", (cpu) => {
			const s = A(cpu, 0);
			const rej = A(cpu, 1);
			let n = 0;
			outer: for (;;) {
				const b = Number(this.mem.read(s + n, 1));
				if (b === 0) break;
				for (let k = 0;; k++) {
					const d = Number(this.mem.read(rej + k, 1));
					if (d === 0) break;
					if (d === b) break outer;
				}
				n += 1;
			}
			ret(cpu, n);
		});
		const parseInt10 = (p) => {
			let i = 0;
			const b = (k) => Number(this.mem.read(p + k, 1));
			while (b(i) === 32 || b(i) >= 9 && b(i) <= 13) i += 1;
			let neg = false;
			if (b(i) === 45) {
				neg = true;
				i += 1;
			} else if (b(i) === 43) i += 1;
			let v = 0;
			for (;;) {
				const c = b(i);
				if (c < 48 || c > 57) break;
				v = v * 10 + (c - 48);
				i += 1;
			}
			return neg ? -v : v;
		};
		hook("atoi", (cpu) => ret32(cpu, parseInt10(A(cpu, 0))));
		hook("atoll", (cpu) => ret(cpu, BigInt(parseInt10(A(cpu, 0)))));
		const strToInt = (p, base, signed) => {
			const b = (k) => Number(this.mem.read(p + k, 1));
			let i = 0;
			while (b(i) === 32 || b(i) >= 9 && b(i) <= 13) i += 1;
			let neg = false;
			if (b(i) === 45) {
				neg = true;
				i += 1;
			} else if (b(i) === 43) i += 1;
			let radix = base;
			if ((radix === 0 || radix === 16) && b(i) === 48 && (b(i + 1) | 32) === 120) {
				radix = 16;
				i += 2;
			} else if (radix === 0) radix = b(i) === 48 ? 8 : 10;
			const big = BigInt(radix);
			let v = 0n;
			for (;;) {
				const c = b(i);
				let d = -1;
				if (c >= 48 && c <= 57) d = c - 48;
				else if (c >= 97 && c <= 122) d = c - 97 + 10;
				else if (c >= 65 && c <= 90) d = c - 65 + 10;
				if (d < 0 || d >= radix) break;
				v = v * big + BigInt(d);
				i += 1;
			}
			if (neg) v = -v;
			return [signed ? BigInt.asIntN(64, v) : BigInt.asUintN(64, v), p + i];
		};
		const doStrTo = (cpu, signed) => {
			const [v, end] = strToInt(A(cpu, 0), A(cpu, 2), signed);
			const ep = A(cpu, 1);
			if (ep) wr(ep, 8, end);
			ret(cpu, v);
		};
		for (const n of [
			"strtol",
			"strtoll",
			"strtoimax"
		]) hook(n, (cpu) => doStrTo(cpu, true));
		hook("strtoull", (cpu) => doStrTo(cpu, false));
		hook("strtod", (cpu) => {
			const p = A(cpu, 0);
			const s = cstr(p);
			const m = /^\s*[-+]?(\d+\.?\d*([eE][-+]?\d+)?|\.\d+([eE][-+]?\d+)?)/.exec(s);
			const ep = A(cpu, 1);
			if (ep) wr(ep, 8, p + (m ? Buffer.byteLength(m[0]) : 0));
			const dv = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(8));
			dv.setFloat64(0, m ? Number(m[0]) : 0, true);
			ret(cpu, dv.getBigUint64(0, true));
		});
		const strtokSave = this.coldAlloc(8);
		const strtokR = (s, delim, save) => {
			const isDelim = (c) => {
				for (let k = 0;; k++) {
					const d = Number(this.mem.read(delim + k, 1));
					if (d === 0) return false;
					if (d === c) return true;
				}
			};
			let p = s !== 0 ? s : rd(save, 8);
			if (!p) return 0;
			while (Number(this.mem.read(p, 1)) !== 0 && isDelim(Number(this.mem.read(p, 1)))) p += 1;
			if (Number(this.mem.read(p, 1)) === 0) {
				wr(save, 8, 0);
				return 0;
			}
			const start = p;
			while (Number(this.mem.read(p, 1)) !== 0 && !isDelim(Number(this.mem.read(p, 1)))) p += 1;
			if (Number(this.mem.read(p, 1)) === 0) wr(save, 8, 0);
			else {
				this.mem.write(p, 1, 0n);
				wr(save, 8, p + 1);
			}
			return start;
		};
		hook("strtok_r", (cpu) => ret(cpu, strtokR(A(cpu, 0), A(cpu, 1), A(cpu, 2))));
		hook("strtok", (cpu) => ret(cpu, strtokR(A(cpu, 0), A(cpu, 1), strtokSave)));
		for (const n of [
			"pthread_mutex_init",
			"pthread_mutex_destroy",
			"pthread_mutex_lock",
			"pthread_mutex_trylock",
			"pthread_mutex_unlock",
			"pthread_mutexattr_init",
			"pthread_mutexattr_destroy",
			"pthread_mutexattr_settype",
			"pthread_cond_init",
			"pthread_cond_destroy",
			"pthread_cond_signal",
			"pthread_cond_broadcast",
			"pthread_cond_wait",
			"pthread_cond_timedwait",
			"pthread_rwlock_rdlock",
			"pthread_rwlock_wrlock",
			"pthread_rwlock_unlock",
			"pthread_detach",
			"pthread_join"
		]) hook(n, (cpu) => ret32(cpu, 0));
		hook("pthread_self", (cpu) => ret(cpu, cpu.tpidr));
		hook("pthread_create", (cpu) => {
			const tp = A(cpu, 0);
			if (tp) wr(tp, 8, cpu.tpidr);
			ret32(cpu, 0);
		});
		hook("pthread_key_create", (cpu) => {
			const p = A(cpu, 0);
			const key = this.coldKeySeq;
			this.coldKeySeq += 1;
			if (p) wr(p, 4, key);
			ret32(cpu, 0);
		});
		hook("pthread_key_delete", (cpu) => {
			this.coldTls.delete(A(cpu, 0));
			ret32(cpu, 0);
		});
		hook("pthread_getspecific", (cpu) => ret(cpu, this.coldTls.get(A(cpu, 0)) ?? 0));
		hook("pthread_setspecific", (cpu) => {
			this.coldTls.set(A(cpu, 0), A(cpu, 1));
			ret32(cpu, 0);
		});
		hook("pthread_once", (cpu) => {
			const p = A(cpu, 0);
			const fn = A(cpu, 1);
			if (rd(p, 4) === 0) {
				wr(p, 4, 1);
				if (fn) this.coldInvoke(fn, []);
			}
			ret32(cpu, 0);
		});
		hook("printf", (cpu) => {
			const s = this.coldVFormat(cstr(A(cpu, 0)), this.coldRegArgs(cpu, 1));
			if (this.verbose) console.log(`[libc] ${s}`);
			ret32(cpu, s.length);
		});
		hook("fprintf", (cpu) => {
			const s = this.coldVFormat(cstr(A(cpu, 1)), this.coldRegArgs(cpu, 2));
			if (this.verbose) console.log(`[libc] ${s}`);
			ret32(cpu, s.length);
		});
		hook("vfprintf", (cpu) => {
			const s = this.coldVFormat(cstr(A(cpu, 1)), new VaList(this.mem, A(cpu, 2), ""));
			if (this.verbose) console.log(`[libc] ${s}`);
			ret32(cpu, s.length);
		});
		hook("vsnprintf", (cpu) => {
			const va = A(cpu, 3);
			if (process.env.SO_FMTLOG && cstr(A(cpu, 2)).includes("llu")) {
				const raw = Buffer.from(this.mem.slice(va, 32)).toString("hex");
				const grTop = Number(this.mem.read(va + 8, 8));
				let grOff = s32(Number(this.mem.read(va + 24, 4)));
				const vals = [];
				for (let i = 0; i < 5; i++) {
					const a = Number(this.mem.read(grTop + grOff, 8));
					grOff += 8;
					vals.push(`0x${a.toString(16)}`);
				}
				const ptr = Number(this.mem.read(grTop + s32(Number(this.mem.read(va + 24, 4))) + 32, 8));
				const mem5 = Buffer.from(this.mem.slice(ptr, 48)).toString("hex");
				writeFileSync("d:/there/douyinhook/unidbg_work/fmtlog.txt", `va=0x${va.toString(16)} raw=${raw} args=${vals.join(",")} mem5=${mem5}\n`, { flag: "a" });
			}
			const s = this.coldVFormat(cstr(A(cpu, 2)), new VaList(this.mem, va, ""));
			ret32(cpu, writeStr(A(cpu, 0), s, A(cpu, 1)));
		});
		hook("__vsnprintf_chk", (cpu) => {
			const s = this.coldVFormat(cstr(A(cpu, 4)), new VaList(this.mem, A(cpu, 5), ""));
			ret32(cpu, writeStr(A(cpu, 0), s, A(cpu, 1)));
		});
		hook("__vsprintf_chk", (cpu) => {
			const s = this.coldVFormat(cstr(A(cpu, 3)), new VaList(this.mem, A(cpu, 4), ""));
			ret32(cpu, writeStr(A(cpu, 0), s, A(cpu, 2)));
		});
		const doAsprintf = (cpu, strp, s) => {
			const b = Buffer.from(s, "utf8");
			const q = this.coldAlloc(b.length + 1);
			if (b.length) this.mem.load(q, b);
			this.mem.write(q + b.length, 1, 0n);
			wr(strp, 8, q);
			ret32(cpu, b.length);
		};
		hook("asprintf", (cpu) => {
			doAsprintf(cpu, A(cpu, 0), this.coldVFormat(cstr(A(cpu, 1)), this.coldRegArgs(cpu, 2)));
		});
		hook("vasprintf", (cpu) => {
			doAsprintf(cpu, A(cpu, 0), this.coldVFormat(cstr(A(cpu, 1)), new VaList(this.mem, A(cpu, 2), "")));
		});
		hook("fwrite", (cpu) => ret32(cpu, A(cpu, 2)));
		hook("fputc", (cpu) => ret32(cpu, A(cpu, 0)));
		hook("fflush", (cpu) => ret32(cpu, 0));
		hook("fopen", (cpu) => {
			const path = cstr(A(cpu, 0));
			const fd = this.sysOpen(path);
			if (this.verbose) console.log(`[libc] fopen(${JSON.stringify(path)}) => fd ${fd}`);
			if (fd < 0) {
				ret(cpu, 0);
				return;
			}
			const h = 1811939328 + fd;
			this.coldFiles.set(h, fd);
			ret(cpu, h);
		});
		hook("fread", (cpu) => {
			const size = A(cpu, 1);
			const n = A(cpu, 2);
			const fd = this.coldFiles.get(A(cpu, 3));
			if (fd === void 0) {
				ret(cpu, 0);
				return;
			}
			const got = Math.max(0, this.sysRead(fd, A(cpu, 0), size * n));
			ret(cpu, size > 0 ? Math.floor(got / size) : 0);
		});
		hook("fclose", (cpu) => {
			const h = A(cpu, 0);
			const fd = this.coldFiles.get(h);
			if (fd !== void 0) {
				this.coldFiles.delete(h);
				this.fds.delete(fd);
			}
			ret32(cpu, 0);
		});
		hook("sscanf", (cpu) => ret32(cpu, 0));
		hook("strerror_r", (cpu) => {
			writeStr(A(cpu, 1), `errno ${A(cpu, 0)}`, A(cpu, 2));
			ret32(cpu, 0);
		});
		hook("getpid", (cpu) => ret32(cpu, this.pid));
		hook("getppid", (cpu) => ret32(cpu, this.pid));
		hook("gettid", (cpu) => ret32(cpu, this.pid));
		hook("getuid", (cpu) => ret32(cpu, 0));
		hook("getpagesize", (cpu) => ret32(cpu, 4096));
		hook("sysconf", (cpu) => {
			const k = A(cpu, 0);
			ret32(cpu, k === 39 ? 4096 : k === 96 || k === 97 ? 8 : 0);
		});
		hook("getenv", (cpu) => ret(cpu, 0));
		hook("__errno", (cpu) => ret(cpu, Number(cpu.tpidr) + 16));
		hook("__system_property_find", (cpu) => ret(cpu, 0));
		hook("__system_property_get", (cpu) => {
			const v = A(cpu, 1);
			if (v) this.mem.write(v, 1, 0n);
			ret32(cpu, 0);
		});
		hook("__system_property_read", (cpu) => ret32(cpu, 0));
		hook("__open_2", (cpu) => {
			const path = cstr(A(cpu, 0));
			const fd = this.sysOpen(path);
			if (this.verbose) console.log(`[libc] open(${JSON.stringify(path)}) => ${fd}`);
			ret32(cpu, fd);
		});
		hook("read", (cpu) => ret(cpu, BigInt.asUintN(64, BigInt(this.sysRead(A(cpu, 0), A(cpu, 1), A(cpu, 2))))));
		hook("__read_chk", (cpu) => ret(cpu, BigInt.asUintN(64, BigInt(this.sysRead(A(cpu, 0), A(cpu, 1), A(cpu, 2))))));
		hook("close", (cpu) => {
			this.fds.delete(A(cpu, 0));
			ret32(cpu, 0);
		});
		hook("fstat", (cpu) => {
			this.sysFstat(A(cpu, 0), A(cpu, 1));
			ret32(cpu, 0);
		});
		hook("mmap", (cpu) => ret(cpu, this.coldMmap(A(cpu, 0), A(cpu, 1))));
		hook("munmap", (cpu) => ret32(cpu, 0));
		hook("mprotect", (cpu) => ret32(cpu, 0));
		hook("uname", (cpu) => {
			if (A(cpu, 0)) this.mem.load(A(cpu, 0), /* @__PURE__ */ new Uint8Array(390));
			ret32(cpu, 0);
		});
		hook("sysinfo", (cpu) => {
			if (A(cpu, 0)) this.mem.load(A(cpu, 0), /* @__PURE__ */ new Uint8Array(112));
			ret32(cpu, 0);
		});
		hook("syscall", (cpu) => {
			const nr = A(cpu, 0);
			for (let i = 0; i < 6; i++) cpu.x[i] = cpu.x[i + 1];
			cpu.x[8] = BigInt(nr);
			this.coldSyscall(cpu, nr);
			cpu.pc = Number(cpu.x[30]);
		});
		for (const n of [
			"access",
			"stat",
			"lstat",
			"fstatat",
			"mkdir",
			"unlink",
			"remove",
			"readlink",
			"ioctl",
			"socket",
			"bind",
			"connect",
			"sendto",
			"recvfrom",
			"setsockopt",
			"inet_addr",
			"fork",
			"system"
		]) hook(n, (cpu) => ret32(cpu, -1));
		for (const n of [
			"opendir",
			"readdir",
			"popen"
		]) hook(n, (cpu) => ret(cpu, 0));
		for (const n of [
			"__cxa_atexit",
			"__cxa_finalize",
			"__cxa_thread_atexit_impl",
			"kill",
			"sigaction",
			"sigprocmask",
			"sigaddset",
			"sigemptyset",
			"prctl",
			"getauxval",
			"openlog",
			"closelog",
			"syslog",
			"android_set_abort_message",
			"closedir",
			"dlclose",
			"dl_iterate_phdr"
		]) hook(n, (cpu) => ret32(cpu, 0));
		hook("dlopen", (cpu) => ret(cpu, 1795162113));
		hook("dlsym", (cpu) => ret(cpu, this.coldGlobals.get(cstr(A(cpu, 1))) ?? 0));
		hook("__stack_chk_fail", () => {
			throw new Error("__stack_chk_fail：栈保护被触发");
		});
		hook("abort", () => {
			throw new Error("abort()");
		});
	}
	/** 签名阶段：按 oracle dlmalloc 序列回放地址（返回 0 表示未命中） */
	replayAlloc(name, n) {
		const list = this.replayList;
		const eq = (i) => i < list.length && list[i].name === name && list[i].n === n;
		let j = -1;
		if (eq(this.replayIdx)) j = this.replayIdx;
		else if (eq(this.replayIdx + 1)) {
			if (process.env.SO_MALLLOG) writeFileSync("d:/there/douyinhook/unidbg_work/malllog.txt", `SKIP ${list[this.replayIdx].name} n=${list[this.replayIdx].n} idx=${this.replayIdx}\n`, { flag: "a" });
			j = this.replayIdx + 1;
		}
		if (j < 0) return 0;
		this.replayIdx = j + 1;
		const p = list[j].addr;
		this.coldAllocs.set(p, n);
		if (name === "calloc") this.mem.fill(p, 0, n);
		if (process.env.SO_MALLLOG) writeFileSync("d:/there/douyinhook/unidbg_work/malllog.txt", `HIT ${name} n=${n} idx=${j} ret=0x${p.toString(16)}\n`, { flag: "a" });
		return p;
	}
	/** 载入 dlmalloc 分配序列（内嵌常量；SO_REPLAY 可覆盖为 alloc_or.txt 原始日志） */
	loadReplay() {
		if (this.replayList.length) return;
		const path = process.env.SO_REPLAY;
		const txt = path ? readFileSync(path, "utf8") : ALLOC_REPLAY;
		const re = path ? /^(\w+) n=(\d+) ret=0x([0-9a-f]+)/ : /^(\w+) (\d+) ([0-9a-f]+)/;
		for (const line of txt.split(/\r?\n/)) {
			const m = re.exec(line);
			if (m) this.replayList.push({
				name: m[1],
				n: Number(m[2]),
				addr: parseInt(m[3], 16)
			});
		}
		this.replayOn = this.replayList.length > 0;
	}
	/** bump 分配（页已在 loadCold 里预映射，内容天然为 0） */
	coldAlloc(n) {
		const size = Math.max(16, n + 15 & -16);
		const p = this.coldHeap;
		if (p + size > 1442840576) throw new Error("冷启动堆耗尽");
		this.coldHeap = p + size;
		this.coldAllocs.set(p, n);
		if (process.env.SO_ALLOCLOG) writeFileSync("d:/there/douyinhook/unidbg_work/alloclog.txt", `0x${p.toString(16)} n=${n} lr=${(Number(this.cpu.x[30]) - SO_BASE).toString(16)}\n`, { flag: "a" });
		return p;
	}
	/** 嵌套调用 so 函数（pthread_once 等回调），保存/恢复全部现场 */
	coldInvoke(entry, args, budget = this.maxSteps) {
		const cpu = this.cpu;
		const st = cpu.saveRegs();
		const nzcv = cpu.nzcv;
		const pc = cpu.pc;
		const tick = cpu.tick;
		const depth = this.coldDepth + 1;
		this.coldDepth = depth;
		for (let i = 0; i <= 30; i++) cpu.x[i] = 0n;
		for (let i = 0; i < args.length && i < 8; i++) cpu.x[i] = BigInt.asUintN(64, BigInt(args[i]));
		cpu.x[30] = BigInt(this.coldSentinel);
		cpu.x[31] = BigInt(this.coldSp - depth * 32768);
		cpu.pc = entry;
		cpu.tick = budget;
		let n = 0;
		try {
			for (;;) {
				if (cpu.pc === this.coldSentinel) break;
				const h = this.pcHooks.get(cpu.pc);
				if (h && h(cpu)) continue;
				if (n >= budget) throw new Error(`冷启动嵌套调用预算耗尽 @0x${cpu.pc.toString(16)}`);
				cpu.step();
				n += 1;
				this.steps += 1;
			}
			return Number(cpu.x[0]);
		} finally {
			cpu.restoreRegs(st);
			cpu.nzcv = nzcv;
			cpu.pc = pc;
			cpu.tick = tick;
			this.coldDepth = depth - 1;
		}
	}
	/** asprintf/printf 的取参：x<start..7> 然后栈 */
	coldRegArgs(cpu, start) {
		let gi = start;
		let fi = 0;
		let sp = Number(cpu.x[31]);
		const dv = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(8));
		return {
			int: (size) => {
				let v;
				if (gi < 8) {
					v = Number(cpu.x[gi]);
					gi += 1;
				} else {
					v = Number(this.mem.read(sp, 8));
					sp += 8;
				}
				return size === 8 ? v : v >>> 0;
			},
			fp: () => {
				if (fi < 8) {
					dv.setBigUint64(0, cpu.v[2 * fi], true);
					fi += 1;
				} else {
					dv.setBigUint64(0, this.mem.read(sp, 8), true);
					sp += 8;
				}
				return dv.getFloat64(0, true);
			}
		};
	}
	/** 最小 printf 格式化：%d %i %u %x %X %o %c %s %p %f %e %g %% + 宽度/精度/标志 */
	coldVFormat(fmt, a) {
		const out = [];
		for (let i = 0; i < fmt.length; i++) {
			const ch = fmt[i];
			if (ch !== "%") {
				out.push(ch);
				continue;
			}
			let j = i + 1;
			if (fmt[j] === "%") {
				out.push("%");
				i = j;
				continue;
			}
			let flags = "";
			while (j < fmt.length && "-+ #0".includes(fmt[j])) {
				flags += fmt[j];
				j += 1;
			}
			let width = 0;
			if (fmt[j] === "*") {
				width = a.int(4) | 0;
				j += 1;
				if (width < 0) {
					flags += "-";
					width = -width;
				}
			} else while (fmt[j] >= "0" && fmt[j] <= "9") {
				width = width * 10 + fmt.charCodeAt(j) - 48;
				j += 1;
			}
			let prec = -1;
			if (fmt[j] === ".") {
				j += 1;
				prec = 0;
				if (fmt[j] === "*") {
					prec = a.int(4) | 0;
					j += 1;
				} else while (fmt[j] >= "0" && fmt[j] <= "9") {
					prec = prec * 10 + fmt.charCodeAt(j) - 48;
					j += 1;
				}
			}
			let len = "";
			while (j < fmt.length && "hljztL".includes(fmt[j])) {
				len += fmt[j];
				j += 1;
			}
			const conv = fmt[j] ?? "";
			i = j;
			const wide = len === "l" || len === "ll" || len === "j" || len === "z" || len === "t";
			let s;
			let negative = false;
			switch (conv) {
				case "d":
				case "i": {
					const raw = wide ? BigInt.asIntN(64, BigInt(a.int(8))) : BigInt(a.int(4) | 0);
					negative = raw < 0n;
					s = (negative ? -raw : raw).toString(10);
					break;
				}
				case "u":
					s = (wide ? BigInt.asUintN(64, BigInt(a.int(8))) : BigInt(a.int(4) >>> 0)).toString(10);
					break;
				case "x":
				case "X":
				case "o":
					s = (wide ? BigInt.asUintN(64, BigInt(a.int(8))) : BigInt(a.int(4) >>> 0)).toString(conv === "o" ? 8 : 16);
					if (conv === "X") s = s.toUpperCase();
					if (flags.includes("#")) s = (conv === "o" ? "0" : conv === "x" ? "0x" : "0X") + s;
					break;
				case "p":
					s = "0x" + a.int(8).toString(16);
					break;
				case "c":
					s = String.fromCharCode(a.int(4) & 255);
					break;
				case "s": {
					const p = a.int(8);
					s = p ? this.mem.cstr(p) : "(null)";
					if (prec >= 0) s = s.slice(0, prec);
					break;
				}
				case "f":
				case "F":
				case "e":
				case "E":
				case "g":
				case "G": {
					const d = a.fp();
					s = conv === "f" || conv === "F" ? d.toFixed(prec >= 0 ? prec : 6) : String(d);
					if (conv === "E" || conv === "G") s = s.toUpperCase();
					if (s.startsWith("-")) {
						negative = true;
						s = s.slice(1);
					}
					break;
				}
				default: s = "%" + conv;
			}
			if (prec >= 0 && "diuxXo".includes(conv)) while (s.length < prec) s = "0" + s;
			const sign = negative ? "-" : flags.includes("+") && "di".includes(conv) ? "+" : flags.includes(" ") && "di".includes(conv) ? " " : "";
			let body = sign + s;
			if (width > body.length) {
				const pad = width - body.length;
				if (flags.includes("-")) body += " ".repeat(pad);
				else if (flags.includes("0") && prec < 0) body = sign + "0".repeat(pad) + s;
				else body = " ".repeat(pad) + body;
			}
			out.push(body);
		}
		const res = out.join("");
		if (process.env.SO_FMTLOG && res.length) {
			const pc = this.cpu ? this.cpu.pc - SO_BASE : 0;
			const lr = this.cpu ? Number(this.cpu.x[30]) - SO_BASE : 0;
			let frames = "";
			if (fmt.includes("llu") && this.cpu) {
				const fs = [];
				let fp = Number(this.cpu.x[29]);
				for (let k = 0; k < 10 && fp; k++) {
					const prev = Number(this.mem.read(fp, 8));
					const ra = Number(this.mem.read(fp + 8, 8));
					fs.push((ra - SO_BASE).toString(16));
					if (prev <= fp) break;
					fp = prev;
				}
				frames = ` frames=${fs.join("<")}`;
			}
			writeFileSync("d:/there/douyinhook/unidbg_work/fmtlog.txt", `pc=${pc.toString(16)} lr=${lr.toString(16)}${frames}\t${fmt}\t=>\t${res}\n`, { flag: "a" });
		}
		return res;
	}
	runCold() {
		const c = this.opts.cold;
		this.loadCold();
		this.coldBuildJni();
		this.installHooks();
		const cpu = this.cpu;
		cpu.svc = (cc, imm) => this.onSvc(cc, imm);
		if (this.verbose) console.log(`[cold] init_array=${this.coldInitArray.length} JNI_OnLoad=0x${this.coldJniOnLoad.toString(16)}`);
		for (let i = 0; i < this.coldInitArray.length; i++) {
			const fn = this.coldInitArray[i];
			if (this.verbose) console.log(`[cold] init_array[${i}] 0x${fn.toString(16)}`);
			this.coldCall(fn, []);
		}
		this.patchInitTime();
		if (this.coldJniOnLoad) {
			const v = this.coldCall(this.coldJniOnLoad, [this.coldVm, 0]);
			if (this.verbose) console.log(`[cold] JNI_OnLoad -> 0x${v.toString(16)}`);
		}
		const exp = this.coldMeta.exports.get("Java_com_bytedance_mobsec_metasec_ml_MS_b");
		this.coldEntry = this.coldNative.get("b") ?? (exp ? 1073741824 + exp : 1076474548);
		if (!this.coldEntry) throw new Error("冷启动：找不到 native b（RegisterNatives/导出都没有）");
		const devId = c.deviceId ?? "3933425002887372";
		const insId = c.installId ?? "2486456434296203";
		const str = (s) => this.newHandle({
			kind: "string",
			val: s
		});
		const verBytes = new Uint8Array([
			51,
			102,
			20,
			15,
			90,
			126,
			121,
			69,
			54,
			43,
			117,
			103,
			13,
			67,
			30,
			41,
			49,
			28,
			122
		]);
		this.cpu.histOn = !!process.env.SO_HIST;
		this.coldB(16777219, 0, 0, 0, this.coldApplication);
		this.coldB(33554449, 0, 0, str(""), 0);
		const verH = this.coldB(16777217, 0, 0, str("443549"), this.newHandle({
			kind: "bytearray",
			val: verBytes
		}));
		const verObj = this.obj(verH);
		const probedVer = verObj && verObj.kind === "string" ? String(verObj.val) : "v04.10.04.01-bugfix";
		if (this.verbose) console.log(`[cold] s4.LIZ -> ${probedVer}`);
		const cfgStr = `["1128","","","${LICENSE}","${probedVer}","","","","","","0","-1","810","","0",[],["tk_key","douyin"]]`;
		this.coldB(67108865, 0, 0, str(cfgStr), 0);
		const hH = this.coldB(67108866, 0, 0, 0, 0);
		const hObj = this.obj(hH);
		const handle2 = hObj && (hObj.kind === "long" || hObj.kind === "object") ? Number(hObj.val) : 0;
		if (this.verbose) console.log(`[cold] handle2=0x${handle2.toString(16)}`);
		this.coldB(33554434, 0, handle2, str(devId), 0);
		this.coldB(33554435, 0, handle2, str(insId), 0);
		this.coldB(33554446, 0, handle2, str(devId), 0);
		this.coldB(33554448, 1, handle2, str("[]"), 0);
		this.coldB(33554441, 0, handle2, 0, 0);
		this.coldB(33554447, 0, handle2, str(""), this.coldApplication);
		this.coldB(33554433, 0, handle2, str(""), str(""));
		const urlH = str(this.opts.url);
		this.urlHandle = urlH;
		const bodyH = this.opts.bodyBytes ? this.newHandle({
			kind: "bytearray",
			val: this.opts.bodyBytes
		}) : this.opts.body ? this.newHandle({
			kind: "string",
			val: this.opts.body
		}) : 0;
		if (this.warmOnly) {
			this.warmOnly = false;
			this.saveBaseline(handle2);
			return {
				headers: {},
				stopReason: "warm",
				steps: this.steps,
				jniCalls: { ...this.jniCount },
				syscalls: [...new Set(this.svcLog)].sort((a, b) => a - b),
				newStrings: this.nstr,
				retObj: void 0
			};
		}
		const r1 = this.coldB(33554442, 0, handle2, urlH, 0);
		if (process.env.SO_STEPLOG) console.log(`[cold] setUrl ret=0x${r1.toString(16)} steps=${this.steps}`);
		if (c.dumpDir) this.dumpColdSegs(c.dumpDir);
		if (process.env.SO_STEPLOG) console.log(`[step] before-getFeatureHash steps=${this.steps}`);
		const retH = this.coldB(33554438, 0, handle2, urlH, bodyH);
		if (process.env.SO_STEPLOG) console.log(`[step] after-getFeatureHash steps=${this.steps}`);
		if (process.env.SO_CTXLOG) writeFileSync("d:/there/douyinhook/unidbg_work/ctxtrace_ts.txt", this.ctxTrace.join("\n") + "\n");
		if (process.env.SO_WATCHADDR) writeFileSync("d:/there/douyinhook/unidbg_work/watchaddr.txt", this.ctxTrace.join("\n") + "\n");
		if (c.dumpDir) this.dumpColdSegs(`${c.dumpDir}_after`);
		if (process.env.SO_DUMPAT) for (const spec of process.env.SO_DUMPAT.split(";")) {
			const [as, ls] = spec.split(",");
			const a = Number.parseInt(as, 16);
			const l = Number.parseInt(ls, 16);
			writeFileSync(`d:/there/douyinhook/unidbg_work/dumpat_${a.toString(16)}.bin`, Buffer.from(this.mem.slice(a, l)));
		}
		const retObj = this.obj(retH);
		const headers = this.parseHeaders(retH);
		if (process.env.SO_HIST) {
			const h = this.cpu.hist;
			const parts = [];
			for (let i = 0; i < h.length; i++) if (h[i] !== 0) parts.push(`${i}:${h[i]}`);
			console.log(`[hist] ${parts.join(" ")}`);
		}
		return {
			headers,
			stopReason: `cold: ${Object.keys(headers).length} headers`,
			steps: this.steps,
			jniCalls: { ...this.jniCount },
			syscalls: [...new Set(this.svcLog)].sort((a, b) => a - b),
			newStrings: this.nstr,
			retObj
		};
	}
	/** 冷启动：加载 so → 建 JNIEnv → 装钩子 → 跑 init_array / JNI_OnLoad，只执行一次 */
	coldStart() {
		if (this.coldStarted) return;
		if (!this.opts.cold) throw new Error("coldStart 只支持冷启动配置（opts.cold）");
		this.loadCold();
		this.coldBuildJni();
		this.installHooks();
		this.cpu.svc = (cc, imm) => this.onSvc(cc, imm);
		for (const fn of this.coldInitArray) this.coldCall(fn, []);
		if (this.coldJniOnLoad) this.coldCall(this.coldJniOnLoad, [this.coldVm, 0]);
		this.coldStarted = true;
	}
	/** 调用 so 静态注册的 native 函数，返回 x0（参数按真机 JNI 形态排列） */
	coldFn(name, args) {
		const fn = this.coldNative.get(name);
		if (fn === void 0) throw new Error(`so 未导出 ${name}`);
		this.coldStart();
		return this.coldCall(fn, args);
	}
	/** 按 ELF 导出名调用 so 函数（走 Java_ 静态注册、不用 RegisterNatives 的 so 用这个） */
	coldExport(name, args) {
		const off = this.coldMeta?.exports.get(name);
		if (off === void 0) throw new Error(`so 未导出 ${name}`);
		this.coldStart();
		return this.coldCall(SO_BASE + off, args);
	}
	/** JNIEnv / class 桩地址：native 的 x0、x1 按真机约定传这两个 */
	get coldEnvAddr() {
		return this.coldEnv;
	}
	get coldClassAddr() {
		return this.coldClassHandle;
	}
	/** 新建 Java 对象句柄 / 读回句柄内容 */
	makeHandle(obj) {
		return this.newHandle(obj);
	}
	readHandle(h) {
		return this.obj(h);
	}
	/**
	* 预热：只跑一遍初始化序列（init_array/JNI_OnLoad/配置），停在 getFeatureHash 入口前。
	* 之后可反复 signFast：每次只恢复基线内存 + 跑一次 getFeatureHash（约 1/3 指令量，
	* JIT 块已全编译），冷启动的 1.1s 只付一次。
	*/
	warmUp() {
		if (!this.opts.cold) throw new Error("warmUp 只支持冷启动配置（opts.cold）");
		if (!this.ts || this.ts <= 0) this.ts = Math.floor(Date.now() / 1e3);
		this.warmOnly = true;
		this.runCold();
	}
	/** 在预热基线上签名（POST 用 body.text / body.bytes，对应 String / byte[]） */
	signFast(url, body, ts) {
		if (!this.baseline) throw new Error("还没 warmUp()");
		const b = this.baseline;
		this.opts.url = url;
		this.opts.body = body?.text;
		this.opts.bodyBytes = body?.bytes;
		this.ts = ts ?? Math.floor(Date.now() / 1e3);
		this.restoreBaseline();
		this.patchInitTime();
		this.objs.set(b.urlHandle, {
			kind: "string",
			val: url
		});
		const bodyH = body?.bytes ? this.newHandle({
			kind: "bytearray",
			val: body.bytes
		}) : body?.text ? this.newHandle({
			kind: "string",
			val: body.text
		}) : 0;
		const r1 = this.coldB(33554442, 0, b.handle2, b.urlHandle, 0);
		if (process.env.SO_STEPLOG) console.log(`[fast] setUrl ret=0x${r1.toString(16)} steps=${this.steps}`);
		const s1 = this.steps;
		const retH = this.coldB(33554438, 0, b.handle2, b.urlHandle, bodyH);
		if (process.env.SO_STEPLOG) console.log(`[fast] setUrl=${s1} hash=${this.steps - s1} ret=0x${retH.toString(16)}`);
		const headers = this.parseHeaders(retH);
		return {
			headers,
			stopReason: `warm: ${Object.keys(headers).length} headers`,
			steps: this.steps,
			jniCalls: { ...this.jniCount },
			syscalls: [...new Set(this.svcLog)].sort((a, b2) => a - b2),
			newStrings: this.nstr,
			retObj: this.obj(retH)
		};
	}
	/** 保存 init 完成时的内存页 + 句柄状态（signFast 的恢复原点） */
	saveBaseline(handle2) {
		const pt = this.mem.pt;
		const pages = /* @__PURE__ */ new Map();
		for (let i = 0; i < pt.length; i++) {
			const p = pt[i];
			if (p !== void 0) pages.set(i, p.slice());
		}
		this.baseline = {
			pages,
			objs: new Map(this.objs),
			handle2,
			urlHandle: this.urlHandle,
			nextHandle: this.nextHandle,
			mmapNext: this.mmapNext,
			heap: this.coldHeap,
			monoUs: this.monoUs
		};
	}
	/** 把内存与句柄状态恢复到基线（新增页丢弃，基线页原地覆写以保住 DataView） */
	restoreBaseline() {
		const b = this.baseline;
		const pt = this.mem.pt;
		const dv = this.mem.dv;
		for (let i = 0; i < pt.length; i++) {
			const snap = b.pages.get(i);
			if (snap === void 0) {
				if (pt[i] !== void 0) {
					pt[i] = void 0;
					dv[i] = void 0;
				}
				continue;
			}
			let p = pt[i];
			if (p === void 0) {
				p = /* @__PURE__ */ new Uint8Array(65536);
				pt[i] = p;
				dv[i] = new DataView(p.buffer);
			}
			p.set(snap);
		}
		this.mem.invalidate();
		this.nextHandle = b.nextHandle;
		this.mmapNext = b.mmapNext;
		this.coldHeap = b.heap;
		this.monoUs = b.monoUs;
		this.objs.clear();
		for (const [k, v] of b.objs) this.objs.set(k, v);
		this.replayIdx = 0;
	}
	/** 返回值（jobject[]）→ 头 map */
	parseHeaders(retH) {
		const headers = {};
		const retObj = this.obj(retH);
		if (retObj && retObj.kind === "objarray") {
			const items = retObj.val;
			for (let i = 0; i + 1 < items.length; i += 2) {
				const k = this.obj(items[i]);
				const v = this.obj(items[i + 1]);
				if (k && k.kind === "string") headers[k.val] = v && v.kind === "string" ? v.val : String(v?.val ?? "");
			}
		}
		return headers;
	}
	/** 调试：按 unidbg 快照的命名把关键区域落盘，便于逐字节 diff */
	dumpColdSegs(dir) {
		mkdirSync(dir, { recursive: true });
		const pt = this.mem.pt;
		let n = 0;
		for (let i = 0; i < pt.length; i++) {
			const p = pt[i];
			if (p === void 0) continue;
			writeFileSync(join(dir, `p_${i.toString(16).padStart(6, "0")}.bin`), Buffer.from(p));
			n += 1;
		}
		if (this.verbose) console.log(`[cold] dump ${n} pages -> ${dir}`);
	}
	coldMmap(addr, len) {
		const size = len + 4095 & -4096;
		let base;
		if (addr !== 0) base = addr & -4096;
		else {
			base = this.mmapNext;
			this.mmapNext = base + size + 65535 & -65536;
		}
		this.mem.map(base, size);
		this.segs.push([base, size]);
		return base;
	}
	/** 冷启动模式的 syscall：与 oracle 对齐，但 mmap/brk 等必须真实现 */
	coldSyscall(cpu, nr) {
		const x0 = Number(cpu.x[0]);
		const x1 = Number(cpu.x[1]);
		const x2 = Number(cpu.x[2]);
		this.svcLog.push(nr);
		switch (nr) {
			case 174:
			case 175:
				cpu.x[0] = 0n;
				return;
			case 172:
			case 173:
			case 178:
			case 96:
				cpu.x[0] = BigInt(this.pid);
				return;
			case 56: {
				const path = this.mem.cstr(x1);
				const fd = this.sysOpen(path);
				if (this.verbose) console.log(`[sys] openat(${JSON.stringify(path)}) => ${fd}`);
				cpu.x[0] = BigInt.asUintN(32, BigInt(fd));
				return;
			}
			case 48:
			case 34:
			case 79:
				cpu.x[0] = 4294967294n;
				return;
			case 80:
				this.sysFstat(x0 & 4294967295, x1);
				cpu.x[0] = 0n;
				return;
			case 63: {
				const n = this.sysRead(x0 & 4294967295, x1, x2);
				cpu.x[0] = BigInt.asUintN(32, BigInt(n));
				return;
			}
			case 64:
				cpu.x[0] = BigInt(x2 & 4294967295);
				return;
			case 57:
				this.fds.delete(x0 & 4294967295);
				cpu.x[0] = 0n;
				return;
			case 113: {
				const [sec, nsec] = x0 === 0 || x0 === 5 ? [this.ts, FROZEN_SUB] : this.monoTime();
				if (x1) {
					this.mem.write(x1, 8, BigInt(sec));
					this.mem.write(x1 + 8, 8, BigInt(nsec));
				}
				cpu.x[0] = 0n;
				return;
			}
			case 169:
				if (x0) {
					this.mem.write(x0, 8, BigInt(this.ts));
					this.mem.write(x0 + 8, 8, BigInt(FROZEN_SUB));
				}
				cpu.x[0] = 0n;
				return;
			case 278: {
				const n = x1 & 4294967295;
				if (x0) this.mem.load(x0, new Uint8Array(n));
				cpu.x[0] = BigInt(n);
				return;
			}
			case 222:
				if (this.verbose) console.log(`[sys] mmap(0x${x0.toString(16)}, 0x${x1.toString(16)}) => -1`);
				cpu.x[0] = BigInt.asUintN(64, -1n);
				return;
			case 215:
			case 226:
			case 233:
			case 98:
			case 99:
			case 167:
			case 25:
			case 29:
			case 46:
			case 62:
			case 124:
			case 123:
			case 131:
			case 129:
			case 130:
			case 135:
				cpu.x[0] = 0n;
				return;
			case 214:
				cpu.x[0] = BigInt.asUintN(64, -1n);
				return;
			case 220:
				cpu.x[0] = BigInt.asUintN(64, -1n);
				return;
			case 78:
				cpu.x[0] = 4294967294n;
				return;
			case 17:
				if (x0) this.mem.load(x0, new Uint8Array([47, 0]));
				cpu.x[0] = BigInt(1);
				return;
			case 160:
				if (x0) this.mem.load(x0, /* @__PURE__ */ new Uint8Array(390));
				cpu.x[0] = 0n;
				return;
			case 261:
			case 157:
				cpu.x[0] = 0n;
				return;
			default:
				if (!this.coldUnknown.has(nr)) {
					this.coldUnknown.add(nr);
					if (this.verbose) console.log(`[sys] cold 未实现 nr=${nr} pc=0x${(cpu.pc - 4).toString(16)} x0=0x${x0.toString(16)} x1=0x${x1.toString(16)} x2=0x${x2.toString(16)} -> 0`);
				}
				cpu.x[0] = 0n;
				return;
		}
	}
};
//#endregion
//#region src/app/so/index.ts
/** x-medusa 真机同源签名：设备注册/激活必须解释执行 libmetasec_ml.so，纯算会被风控判 device_id=0 */
/** 找不到资源时留空，等到真正签名再报错，避免仅导入即崩 */
const root = findAsset("libmetasec_ml.so");
const soPath = root ? join(root, "libmetasec_ml.so") : "";
const libDir = root ? join(root, "lib64") : "";
/** 同一设备身份复用已预热的实例：冷启动约 1s，预热后每次签名约 0.25s */
const pool$1 = /* @__PURE__ */ new Map();
function signerOf(ids, ts) {
	if (!soPath) throw new Error("找不到 assets/libmetasec_ml.so");
	const key = `${ids.deviceId ?? ""}|${ids.installId ?? ""}`;
	const cached = pool$1.get(key);
	if (cached) return cached;
	const signer = new SoSigner({
		cold: {
			soPath,
			libDir,
			deviceId: ids.deviceId ?? "",
			installId: ids.installId ?? ""
		},
		url: "",
		ts
	});
	signer.warmUp();
	pool$1.set(key, signer);
	return signer;
}
/** 生成六神签名头（小写键）；ids 为空表示注册前/匿名会话尚无设备身份 */
function soSign(url, body, ids = {}) {
	const q = new URL(url).searchParams;
	const ts = Number(q.get("ts")) || Math.floor((Number(q.get("tmp")) || Date.now()) / 1e3);
	const headers = signerOf(ids, ts).signFast(url, body ? { bytes: body } : void 0, ts).headers;
	return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
}
//#endregion
//#region src/app/nlog.ts
/** a0_ 设备证明：解释执行 libnative_log.so，生成 NativeLogManager 的 MMapResult */
/** Java_ 静态注册的导出名，直接按 ELF 符号调用 */
const EXPORT = "Java_com_ss_android_deviceregister_nativeManager_NativeLogManager_getMMMapResult";
/** 因子默认值：服务端未下发采集配置时只能填空画像，index 沿用真机配置 */
const FACTORS = [
	[
		"d_i0",
		1,
		() => "{}"
	],
	[
		"d_a0",
		1,
		() => "{}"
	],
	[
		"d_r0",
		1,
		() => "abc"
	],
	[
		"d_b0",
		2,
		() => String(Math.round(Date.now() - uptime() * 1e3))
	],
	[
		"d_m0",
		1,
		() => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	]
];
var Nlog = class {
	so;
	constructor(deviceId) {
		const dir = assetDir("libnative_log.so");
		this.so = new SoSigner({
			cold: {
				soPath: join(dir, "libnative_log.so"),
				libDir: join(dir, "lib64"),
				deviceId,
				installId: ""
			},
			url: "",
			ts: 0
		});
		this.so.coldStart();
	}
	/** 返回紧凑二进制 MMapResult，后续与「_秒」一起做 RSA 加密 */
	mmap(version, tag) {
		const pairs = FACTORS.map(([k, index, value]) => [this.so.makeHandle({
			kind: "string",
			val: k
		}), this.so.makeHandle({
			kind: "json",
			val: {
				index,
				value: value()
			}
		})]);
		const map = this.so.makeHandle({
			kind: "map",
			val: pairs
		});
		const s = this.so.makeHandle({
			kind: "string",
			val: tag
		});
		const h = this.so.coldExport(EXPORT, [
			this.so.coldEnvAddr,
			this.so.coldClassAddr,
			map,
			version,
			0,
			s
		]);
		const o = this.so.readHandle(h);
		if (!o || o.kind !== "bytearray") throw new Error("native_log 未返回 MMapResult");
		return o.val;
	}
};
/** 冷启动解释器代价高，同一设备进程内复用 */
const pool = /* @__PURE__ */ new Map();
function mmap(deviceId, version, tag) {
	let n = pool.get(deviceId);
	if (!n) {
		n = new Nlog(deviceId);
		pool.set(deviceId, n);
	}
	return n.mmap(version, tag);
}
//#endregion
//#region src/app/dtrait.ts
/** 设备证明与场景报告：x-tt-device-dtrait 走 native_log 的 a0_，x-bb-* 走 badger */
/** 登录场景号（BadgerDtraitReporter 里 passport 走的 scene） */
const SCENE = 17;
const be = (n) => [
	n >>> 24 & 255,
	n >>> 16 & 255,
	n >>> 8 & 255,
	n & 255
];
const int = (v) => [1, ...be(v)];
const str = (v) => {
	const b = Buffer.from(v, "utf8");
	return [
		3,
		b.length >> 8 & 255,
		b.length & 255,
		...b
	];
};
const bytes = (b) => [
	4,
	b.length >> 8 & 255,
	b.length & 255,
	...b
];
/** murmur2：Java 侧用它对 deviceId 取 hash 拼挑战原文，换算法挑战值就对不上 */
function m2(data) {
	const len = data.length;
	const n = len >> 2;
	let h = 0;
	for (let i = 0; i < n; i++) {
		const o = i << 2;
		const k = Math.imul((data[o + 3] & 255) << 24 | data[o] & 255 | (data[o + 1] & 255) << 8 | (data[o + 2] & 255) << 16, -862048943);
		h ^= Math.imul(k >>> 17 | k << 15, 461845907);
		h = Math.imul(h >>> 19 | h << 13, 5) - 430675100;
	}
	let k1 = 0;
	const r = len & 3;
	const o = n << 2;
	if (r === 3) k1 = (data[o + 2] & 255) << 16 ^ (data[o + 1] & 255) << 8 ^ data[o] & 255;
	else if (r === 2) k1 = (data[o + 1] & 255) << 8 ^ data[o] & 255;
	else if (r === 1) k1 = data[o] & 255;
	if (r > 0) h ^= Math.imul(k1 << 15 | k1 >>> 17, 461845907);
	h ^= len;
	h = Math.imul(h ^ h >>> 16, -2048144789);
	h = Math.imul(h ^ h >>> 13, -1028477387);
	return (h ^ h >>> 16) >>> 0;
}
/** 响应节点：状态码 + 消息 + 业务数据，全部大端 */
function parse(buf) {
	const out = [];
	const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	let i = 10;
	while (i < buf.length) {
		const t = buf[i++];
		if (t === 1) {
			out.push({
				t,
				v: dv.getInt32(i)
			});
			i += 4;
		} else if (t === 2) {
			out.push({
				t,
				v: dv.getBigInt64(i)
			});
			i += 8;
		} else if (t === 3 || t === 4) {
			const l = buf[i] << 8 | buf[i + 1];
			i += 2;
			out.push({
				t,
				v: t === 3 ? Buffer.from(buf.subarray(i, i + l)).toString("utf8") : buf.subarray(i, i + l)
			});
			i += l;
		} else if (t === 5) out.push({
			t,
			v: buf[i++] === 1 ? 1 : 0
		});
		else break;
	}
	return out;
}
var Badger = class {
	so;
	bridge;
	did;
	constructor(did) {
		const dir = assetDir("libbdbadger.so");
		this.did = did;
		this.so = new SoSigner({
			cold: {
				soPath: join(dir, "libbdbadger.so"),
				libDir: join(dir, "lib64"),
				deviceId: did,
				installId: ""
			},
			url: "",
			ts: 0
		});
		this.so.coldStart();
		this.bridge = this.so.makeHandle({
			kind: "object",
			val: "bridge"
		});
		this.call(2000799499, [32, 33]);
		this.call(2000799499, [
			32,
			1,
			0,
			0,
			0,
			7,
			33
		]);
		this.call(1821380370, str("/data/user/0/com.ss.android.ugc.aweme"));
		this.call(1519260272, str(""));
	}
	/** 生成一份与当前设备绑定的登录场景报告；失败时降级为空（a0_ 才是必需证据） */
	report() {
		try {
			const ts = Date.now();
			const key = String(m2(Buffer.from(this.did, "utf8")));
			const ch = this.call(770215073, bytes(Buffer.from(key + ts, "utf8")));
			const challenge = String(Number(ch[2]?.v ?? 0) >>> 0);
			this.call(224529259, str(this.did));
			const payload = this.call(938517046, [...str(challenge), ...int(SCENE)])[4]?.v;
			return typeof payload === "string" ? payload : "";
		} catch {
			return "";
		}
	}
	call(op, payload) {
		const handle = this.so.makeHandle({
			kind: "bytearray",
			val: new Uint8Array([
				1,
				0,
				...be(op),
				...be(payload.length),
				...payload
			])
		});
		const r = this.so.coldFn("a", [
			this.so.coldEnvAddr,
			this.bridge,
			handle,
			0
		]);
		const o = this.so.readHandle(r);
		if (!o || o.kind !== "bytearray") throw new Error(`badger op ${op} 无返回`);
		return parse(o.val);
	}
};
/** dtrait_pk1 是 Base64(PEM)，PEM 里是 PKCS#1 RSA 公钥 DER */
function pubKey(b64) {
	const body = Buffer.from(b64, "base64").toString("utf8").replace(/-----BEGIN[^-]+-----|-----END[^-]+-----/g, "").replace(/\s+/g, "");
	return createPublicKey({
		key: Buffer.from(body, "base64"),
		format: "der",
		type: "pkcs1"
	});
}
/** a0_：RSA/ECB/PKCS1(mmap + "_" + 秒)，前缀取服务端下发的 dtrait_pk1_version */
function proof(ids, ms) {
	if (!ids.dtrait_pk1) return "";
	const raw = mmap(ids.device_id, ids.dtrait_version ?? 0, "device_register");
	const plain = Buffer.concat([Buffer.from(raw), Buffer.from(`_${Math.floor(ms / 1e3)}`)]);
	const enc = publicEncrypt({
		key: pubKey(ids.dtrait_pk1),
		padding: constants.RSA_PKCS1_PADDING
	}, plain);
	return `${ids.dtrait_pk1_version || "a0"}_${enc.toString("base64")}`;
}
/** 真机同一设备一小时内复用同一份报告，这里按进程缓存；a0_ 每次请求现算，时间戳才新鲜 */
const reports = /* @__PURE__ */ new Map();
function dtrait(ids) {
	const ms = Date.now();
	let data = reports.get(ids.device_id);
	if (data === void 0) {
		data = ids.device_id ? new Badger(ids.device_id).report() : "";
		reports.set(ids.device_id, data);
	}
	return {
		payload: proof(ids, ms),
		signal: String(ms),
		data,
		scene: String(SCENE)
	};
}
//#endregion
//#region src/app/turing.ts
/** bdturing 静默采集：服务端回 40000/nocaptcha_collect 时，按真机算法上报后重试原请求 */
const log$3 = createLog({ tag: "turing" });
const HOST$2 = "verify-zjg.zijieapi.com";
/** 进程启动时刻：上报里的 launch_time/runtime 以它为基准 */
const START = Date.now();
const PAGE = "com.ss.android.ugc.aweme.main.MainActivity";
/** 服务端下发的采集开关，样本各字段恒为 true */
const CONF = {
	async_collect_time_out: 1e4,
	collect_page_history: true,
	collect_page_history_pre: true,
	collect_touch_event: true,
	collect_touch_event_pre: true,
	report_time_out: 2e3,
	trigger_sec_sdk: true,
	use_static_touch_proxy: true
};
const ALPHA = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/**
* 只处理静默采集；10000 属于滑块，交给调用方。
* 40000 实测只在 x-vc-bdturing-parameters 里下发（bdturing-verify 是同一响应里的滑块决策），
* 漏读它等于跳过环境采集，后续 verify 会被判 5014。
*/
function ask(res) {
	for (const name of ["bdturing-verify", "x-vc-bdturing-parameters"]) {
		const raw = res.headers[name];
		if (!raw) continue;
		try {
			const j = JSON.parse(raw);
			if (String(j.code) !== "40000" || String(j.type) !== "verify") continue;
			const detail = String(j.detail ?? "");
			if (!detail) continue;
			return {
				subtype: String(j.subtype ?? ""),
				detail,
				logId: String(j.log_id ?? "")
			};
		} catch {}
	}
}
/** 上报体：真机字段齐全，但触摸轨迹为空（无 UI，服务端只做存在性判断） */
function body(a) {
	const now = Date.now();
	return JSON.stringify({
		data_type: "async_collect",
		common: {
			launch_time: START,
			is_back_ground: false,
			runtime: now - START,
			page_id: PAGE,
			page_history: [{
				id: PAGE,
				et: START,
				lt: 0
			}],
			page_profile: [{
				index: 0,
				ts: START,
				name: PAGE,
				touch_hook: {
					success: 1,
					ts: START
				}
			}],
			first_touch_event: [],
			touch_event: []
		},
		data_profile: {
			page_history_count: 1,
			touch_event_count: 0,
			first_touch_event_count: 0,
			page_profile_count: 1
		},
		sdk_runtime_info: {
			init_pid: process.pid,
			pid: process.pid,
			init_time: START,
			life_cycle_register_time: START,
			th_init_ts: START,
			th_init_result: true,
			th_init_page_id: PAGE
		},
		nocaptcha: CONF,
		async_collect_data: { async_touch_event_start_time: now },
		status_code: 0,
		log_ids: a.logId ? [a.logId] : []
	});
}
/** 09eh：tc 信封 + 随机 nonce + AES-256-GCM，密钥由 nonce 与 detail 的 MD5 双层 SHA512 派生 */
function seal(text, detail) {
	let nonce = "";
	for (let i = 0; i < 32; i++) nonce += ALPHA[randomInt(62)];
	const md5 = createHash("md5").update(detail).digest();
	const seed = createHash("sha512").update(Buffer.concat([createHash("sha512").update(nonce).digest(), md5])).digest();
	const cipher = createCipheriv("aes-256-gcm", seed.subarray(0, 32), seed.subarray(32, 44));
	const plain = Buffer.concat([createHash("sha512").update(text).digest(), Buffer.from(text)]);
	const enc = Buffer.concat([
		cipher.update(plain),
		cipher.final(),
		cipher.getAuthTag()
	]);
	return Buffer.concat([
		Buffer.from([
			116,
			99,
			6,
			16,
			0,
			0
		]),
		Buffer.from(nonce),
		enc
	]).toString("base64");
}
function query$1(a, dev, ids) {
	const q = new URLSearchParams();
	const base = [
		["app_version", dev.versionName],
		["device_model", dev.deviceType],
		["iid", ids.iid ?? ""],
		["channel", dev.channel],
		["device_type", dev.deviceType],
		["locale", "zh_CN"],
		["resolution", dev.resolution],
		["subtype", a.subtype],
		["sdk_version", "4.2.1.cn"],
		["lang", "zh"],
		["orientation", "2"],
		["ch", dev.channel],
		["os_version", dev.osVersion],
		["version_code", String(dev.manifestVersionCode)],
		["vc", dev.versionName],
		["app_name", dev.appName],
		["app_key", ""],
		["version_name", dev.versionName],
		["device_brand", dev.deviceBrand],
		["os_type", "0"],
		["os_name", "android"],
		["device_platform", dev.devicePlatform],
		["detail", a.detail],
		["region", "cn"],
		["aid", String(dev.aid)],
		["did", ids.device_id ?? ""]
	];
	for (const [k, v] of base) q.append(k, v);
	const ms = Date.now();
	q.append("_rticket", String(ms));
	q.append("ts", String(Math.floor(ms / 1e3)));
	return q;
}
async function report(a, dev, ids, auth) {
	const url = `https://${HOST$2}/nocaptcha/report?${query$1(a, dev, ids).toString()}`;
	const headers = [
		["user-agent", ua(dev)],
		["x-ss-dp", String(dev.aid)],
		["x-tt-request-tag", "n=1;t=0;s=1;p=0"],
		["x-bd-kmsv", "1"],
		["x-vc-bdturing-sdk-version", "4.2.1.cn"],
		["content-type", "application/json; charset=utf-8"],
		["accept-encoding", "gzip, deflate, br"]
	];
	const cookie = auth.cookie();
	if (cookie) headers.push(["cookie", cookie]);
	if (ids.device_id) {
		const dt = dtrait(ids);
		if (dt.payload) {
			headers.push(["x-tt-device-dtrait", dt.payload]);
			headers.push(["x-tt-device-signal", dt.signal]);
			headers.push(["x-bb-signal", dt.signal]);
			headers.push(["x-bb-scene", dt.scene]);
		}
		if (dt.data) headers.push(["x-bb-data", dt.data]);
	}
	for (const [k, v] of Object.entries(soSign(url, void 0, {
		deviceId: ids.device_id,
		installId: ids.iid
	}))) headers.push([k, v]);
	try {
		const res = await request({
			url,
			method: "POST",
			headers,
			body: Buffer.from(JSON.stringify({ data: seal(body(a), a.detail) }))
		});
		const ok = Number(res.json?.code ?? 0) === 200;
		if (ok) log$3.info("静默采集已上报");
		else log$3.warn(`静默采集失败 status=${res.status} ${res.text.slice(0, 120)}`);
		return ok;
	} catch (err) {
		log$3.warn(`静默采集异常 ${err.message}`);
		return false;
	}
}
//#endregion
//#region src/app/guard.ts
/** ticket-guard v3 设备证明：优先用同源 profile 材料，缺失时才按设备稳定标识派生 */
/** 真机服务端证书序列号；boot 时原样回带，服务端据此选验签证书 */
const SN = "533240336124694022040808462028007165443034493949";
/** 派生证书没有服务端共享的 ecdh 键，扫码确认后 HMAC 必然对不上 */
const HMAC_KEY = Buffer.alloc(32, 7);
const cache = /* @__PURE__ */ new Map();
let tg;
/** 私钥标量转 P-256 KeyObject；最高位压掉保证落在曲线阶内 */
function keyOf(hex) {
	const d = Buffer.from(hex, "hex");
	d[0] &= 127;
	const ecdh = createECDH("prime256v1");
	ecdh.setPrivateKey(d);
	const pub = ecdh.getPublicKey();
	return {
		key: createPrivateKey({
			key: {
				kty: "EC",
				crv: "P-256",
				d: d.toString("base64url"),
				x: pub.subarray(1, 33).toString("base64url"),
				y: pub.subarray(33, 65).toString("base64url")
			},
			format: "jwk"
		}),
		pub
	};
}
/**
* profile 的证书、ecdh 键与 sec-ts 必须来自同一次真机登记：
* 服务端按 device_id 记住登记材料，跨设备拼装或派生都会在扫码确认阶段判 7。
*/
function load() {
	if (tg !== void 0) return tg;
	tg = null;
	const file = process.env.DY_TG_PROFILE ?? "assets/tg.json";
	if (!existsSync(file)) return tg;
	const raw = JSON.parse(readFileSync(file, "utf8"));
	const t = raw.tee ?? {};
	const path = t.private_key_path;
	if (!raw.ree_private_key || !t.pub_key || !path) return tg;
	const pem = isAbsolute(path) ? path : join(dirname(file), path);
	if (!existsSync(pem)) return tg;
	const ree = keyOf(raw.ree_private_key);
	tg = {
		cert: Buffer.from(`pub.${t.pub_key}`, "utf8").toString("base64"),
		reeKey: ree.pub.toString("base64"),
		tee: createPrivateKey(readFileSync(pem)),
		ree: ree.key,
		ecdh: Buffer.from(raw.ecdh_key ?? "", "base64"),
		sec: t.sec_ts ?? "",
		sn: t.server_cert_sn ?? SN,
		os: raw.display_os_version ?? "",
		tickets: raw.tickets ?? {}
	};
	return tg;
}
function pair(seed, tag) {
	return keyOf(createHash("sha256").update(`${tag}:${seed}`, "utf8").digest("hex"));
}
function guard(ids) {
	const p = load();
	if (p) return {
		cert: p.cert,
		reeKey: p.reeKey,
		tee: p.tee,
		ree: p.ree
	};
	const seed = ids.clientudid || ids.openudid || ids.cdid;
	const hit = cache.get(seed);
	if (hit) return hit;
	const tee = pair(seed, "tee");
	const ree = pair(seed, "ree");
	const g = {
		cert: Buffer.from(`pub.${tee.pub.toString("base64")}`, "utf8").toString("base64"),
		reeKey: ree.pub.toString("base64"),
		tee: tee.key,
		ree: ree.key
	};
	cache.set(seed, g);
	return g;
}
/** IM 信封 PASSPORT_CERT_AUTH(4) 的 cert 与 ree 公钥，必须与请求头同源 */
function zt(ids) {
	const g = guard(ids);
	return {
		cert: g.cert,
		reeKey: g.reeKey
	};
}
/** profile 的 sec-ts 与 tee 证书同源；重新 boot 会换成派生证书，反倒制造不一致 */
function tgSec() {
	return load()?.sec ?? "";
}
/** client-data：字段顺序与真机 Gson 序列化一致，服务端按原文验 HMAC 与签名 */
function clientData(ids, path, ticket, ts) {
	const p = load();
	const tsSign = p ? p.tickets[path]?.ts_sign_ree ?? "" : `ts.1.${sign("sha256", Buffer.from(`ts.1.${ts}`, "utf8"), {
		key: guard(ids).ree,
		dsaEncoding: "ieee-p1363"
	}).toString("hex")}`;
	const reqSign = createHmac("sha256", p?.ecdh.length === 32 ? p.ecdh : HMAC_KEY).update(`ticket=${ticket}&path=${path}&timestamp=${ts}`).digest("base64");
	return Buffer.from(JSON.stringify({
		req_content: "ticket,path,timestamp",
		timestamp: ts,
		ts_sign: "",
		ts_sign_ree: tsSign,
		req_sign: "",
		req_sign_ree: reqSign
	}), "utf8").toString("base64");
}
/** static-sign：真机直接用 tee 私钥对 sec-ts 原文做 SHA256withECDSA；额外哈希或加前缀都会验签失败（响应头 1105） */
function staticSign(ids, sec) {
	return sign("sha256", Buffer.from(sec, "utf8"), { key: guard(ids).tee }).toString("base64");
}
/** 注册请求只带三件套：服务端借此把公钥绑定到 device_id，后续业务请求才认 static-sign */
function regHead(ids, sec) {
	return [
		["bd-ticket-guard-client-cert", guard(ids).cert],
		["bd-ticket-guard-static-sign", staticSign(ids, sec)],
		["bd-ticket-guard-sec-ts", sec]
	];
}
/** 设备证明公共头：boot 用迭代 3 并追加 client-data，业务请求用迭代 2 并追加 sec-ts */
function head$1(dev, ids, iteration, extra = []) {
	const g = guard(ids);
	const p = load();
	return [
		["bd-ticket-guard-version", "3"],
		["bd-ticket-guard-tee-status", "1"],
		["bd-ticket-guard-server-cert-sn", p?.sn || SN],
		["bd-ticket-guard-display-os-version", p?.os || dev.romVersion],
		["bd-ticket-guard-client-cert", g.cert],
		["bd-ticket-guard-ree-public-key", g.reeKey],
		["bd-ticket-guard-iteration-version", String(iteration)],
		...extra
	];
}
//#endregion
//#region src/app/api.ts
/** passport 请求：静态头模板 → 注入会话 → 组 body → SO 签名 → 发送 */
const HOST$1 = "api5-normal-lf.amemv.com";
/** boot 用的设备证明入口 */
const BOOT = "/passport/user_info/get_sec_ts/";
/** 预热入口：真机取码前必带 odin_tt，该接口未登录也会下发 */
const INFO = "/passport/account/info/v2/";
/** odin_tt 有效期约 31s：留余量按 30s 刷新 */
const WARM_TTL = 3e4;
/** sec-ts 有效期约 20~60s：留出余量，过期再取新票 */
const SEC_TTL = 6e4;
/** x-tt-trace-id 是 TTNet 生成的链路号：32hex + 其前 16hex */
function traceId$1() {
	const id = randomBytes(16).toString("hex");
	return `00-${id}-${id.slice(0, 16)}-01`;
}
/** 真机静态头（顺序敏感） */
function base$1(dev, ids) {
	const list = [
		["x-tt-multi-sids", "none"],
		["sdk-version", "2"],
		["passport-sdk-version", "60755"],
		["passport-sdk-settings", "x-tt-token,sec_user_id,device_transfer_s_0,device_transfer_ab_1"],
		["passport-sdk-sign", "x-tt-token,sec_user_id"],
		["x-ss-dp", String(dev.aid)],
		["x-tt-request-tag", "n=0;s=-1;p=0"],
		["x-vc-bdturing-sdk-version", "4.2.1.cn"],
		["x-bd-kmsv", "1"],
		["user-agent", ua(dev)]
	];
	if (ids.device_dtrait) list.splice(1, 0, ["x-tt-device-dtrait", ids.device_dtrait]);
	if (ids.device_dtrait_token) list.splice(1, 0, ["x-tt-device-dtrait-token", ids.device_dtrait_token]);
	if (ids.client_key) list.push(["x-bd-client-key", ids.client_key]);
	return list;
}
function upsert(list, name, value) {
	if (!value) return;
	const i = list.findIndex(([n]) => n.toLowerCase() === name);
	if (i >= 0) list[i] = [list[i][0], value];
	else list.push([name, value]);
}
function query(dev, ids, panel, extra) {
	const q = passportQuery(dev, ids, {
		language: "zh",
		first_launch_timestamp: ids.first_install,
		last_deeplink_update_version_code: 0,
		is_guest_mode: 0,
		app_type: "normal",
		minor_status: 0,
		is_preinstall: 0,
		need_personal_recommend: 1,
		is_android_pad: 0,
		is_android_fold: 0,
		cronet_version: "295fdb87_2026-08-31",
		ttnet_version: "4.2.301.9-douyin",
		...extra
	});
	return panel ? panelQuery(q, panel) : q;
}
/** 取/复用 sec-ts：注册与业务请求共用同一套证明材料，缺票时先 boot */
async function boot(auth, dev, ids) {
	const fixed = tgSec();
	if (fixed) {
		auth.sec = fixed;
		return fixed;
	}
	if (auth.sec && Date.now() - auth.secAt < SEC_TTL) return auth.sec;
	const ts = Math.floor(Date.now() / 1e3);
	const sec = (await once({
		auth,
		dev,
		ids,
		path: BOOT,
		params: { update_scene: "boot" },
		body: "update_scene=boot",
		enc: "zstd",
		guard: false,
		extra: Object.fromEntries(head$1(dev, ids, 2, [["bd-ticket-guard-client-data", clientData(ids, BOOT, "", ts)]]))
	})).headers["bd-ticket-guard-sec-ts"];
	if (sec) {
		auth.sec = sec;
		auth.secAt = Date.now();
	}
	return auth.sec;
}
/** 真机会在正常浏览中拿到 odin_tt（TTNet 反爬 cookie）；全新会话缺失时 passport 会兜底判 7 */
async function warm$1(auth, dev, ids) {
	if (auth.jar.has("odin_tt") && Date.now() - auth.warmAt < WARM_TTL) return;
	auth.warmAt = Date.now();
	await once({
		auth,
		dev,
		ids,
		path: INFO,
		panel: "normal",
		body: null
	});
}
/** 发一条 passport 请求，成功与否都回写会话 cookie/头 */
async function send(init) {
	if (init.guard !== false) {
		await boot(init.auth, init.dev, init.ids);
		await warm$1(init.auth, init.dev, init.ids);
	}
	const res = await once(init);
	if (init.turing === false) return res;
	const a = ask(res);
	if (!a || !await report(a, init.dev, init.ids, init.auth)) return res;
	return once(init);
}
/**
* 端上通用请求头：passport 与 bdturing 请求共用同一套会话与设备证明。
* 真机的 /captcha/get|verify 带完整 passport cookie、x-tt-token、csrf、ticket-guard 头，
* 少了这些挑战票据无法归属到会话，verify 会被判环境异常（5014）。
*/
function headOf(auth, dev, ids, tag, guard = true, extra) {
	const headers = strip$1(base$1(dev, ids));
	const cookie = auth.cookie();
	if (cookie) headers.push(["cookie", cookie]);
	upsert(headers, "x-tt-passport-csrf-token", auth.csrf());
	upsert(headers, "x-tt-dt", ids.device_token);
	upsert(headers, "x-tt-passport-verify-portrait", auth.portrait);
	upsert(headers, "x-tt-passport-verify-portrait-outer", auth.portrait);
	upsert(headers, "x-tt-passport-trace-id", auth.traceId);
	upsert(headers, "x-tt-passport-mfa-token", auth.mfaToken);
	upsert(headers, "d-ticket", auth.dTicket);
	const ms = Date.now();
	upsert(headers, "activity_now_client", String(ms));
	upsert(headers, "x-ss-req-ticket", String(ms));
	upsert(headers, "x-tt-trace-id", traceId$1());
	for (const n of [
		"x-tt-token",
		"x-tt-token-supplement",
		"token-tlb-tag",
		"session-tlb-tag"
	]) upsert(headers, n, auth.tokens[n]);
	upsert(headers, "x-tt-request-tag", tag);
	for (const [k, v] of Object.entries(extra ?? {})) upsert(headers, k.toLowerCase(), v);
	if (guard && auth.sec) for (const [k, v] of head$1(dev, ids, 2, [["bd-ticket-guard-static-sign", staticSign(ids, auth.sec)], ["bd-ticket-guard-sec-ts", auth.sec]])) upsert(headers, k, v);
	return headers;
}
async function once(init) {
	const { auth, dev, ids } = init;
	const q = query(dev, ids, init.panel, init.params);
	if (init.queryOnly && typeof init.body === "string") {
		for (const [k, v] of new URLSearchParams(init.body)) if (!q.has(k)) q.set(k, v);
	}
	const url = buildUrl(HOST$1, init.path, q);
	const headers = headOf(auth, dev, ids, init.tag ?? "n=0;s=-1;p=0", init.guard !== false, init.extra);
	let payload;
	let signText;
	let signBytes;
	const body = init.queryOnly ? null : init.body;
	if (body !== null && body !== void 0) {
		const enc = init.enc ?? "zstd";
		if (Buffer.isBuffer(body)) {
			payload = body;
			signBytes = body;
			headers.push(["content-type", "application/octet-stream"]);
		} else if (enc === "tt") {
			const encrypted = ttEncrypt(Buffer.from(body, "utf8"));
			payload = gzipSync(encrypted);
			signBytes = encrypted;
			headers.push(["content-type", "application/x-www-form-urlencoded; charset=UTF-8"]);
			headers.push(["x-bd-content-encoding", "gzip"]);
			headers.push(["x-tt-encrypt-info", "1"]);
			headers.push(["x-tt-cipher-version", "1.0.0"]);
			headers.push(["x-ss-stub", ssStub(encrypted)]);
		} else {
			const plain = Buffer.from(body, "utf8");
			payload = enc === "zstd" ? zstdCompress(plain) : plain;
			signText = body;
			headers.push(["content-type", "application/x-www-form-urlencoded; charset=UTF-8"]);
			if (enc === "zstd") headers.push(["x-bd-content-encoding", "zstd"]);
			headers.push(["x-ss-stub", ssStub(plain)]);
		}
		headers.push(["content-length", String(payload.length)]);
	}
	headers.push(["accept-encoding", "gzip, deflate"]);
	const sig = soSign(url, signBytes ?? (signText !== void 0 ? Buffer.from(signText, "utf8") : void 0), {
		deviceId: ids.device_id,
		installId: ids.iid
	});
	for (const [k, v] of Object.entries(sig)) if (k !== "x-ss-stub") upsert(headers, k, v);
	const res = await request({
		url,
		method: init.method ?? (payload ? "POST" : "GET"),
		headers,
		body: payload,
		timeoutMs: init.timeoutMs
	});
	auth.absorb(res.setCookie);
	auth.lastHeaders = res.headers;
	auth.take(res.headers);
	return res;
}
//#endregion
//#region src/app/body.ts
/** Passport 登录请求体构造：表单串拼接、手机号规范化、MFA 与扫码表单 */
/** 部分字段已手工编码（mobile 的 %2B86），不能走 encodeURIComponent */
function enc(v) {
	return encodeURIComponent(String(v));
}
function pairs(list) {
	return list.map(([k, v]) => `${k}=${enc(v)}`).join("&");
}
/** 手机号统一成 +86xxxxxxxxxxx（真机 body 带 +86） */
function normalizeMobile(mobile) {
	const m = mobile.replace(/\s/g, "");
	if (m.startsWith("+")) return m;
	return m.length === 11 ? `+86${m}` : m;
}
/** 验证码登录第一步：mobile/send_code；type(24)/unbind_exist 走 XOR，mobile 已手工编码 */
function buildSendCode(mobile, cred = {}) {
	const list = [
		["is_vcd", "1"],
		["reg_cookie_opt", "true"],
		["ttnet_sdk_version", "4.2.301.9-douyin"],
		["auto_read", "0"],
		["auth_sdk_version", "4.7.7-rc.23"],
		["mix_mode", "1"],
		["account_app_language", "zh"],
		["mobile", `%2B86+${enc(mobile.replace(/\s/g, "").replace(/^\+86/, ""))}`]
	];
	if (cred.captcha) list.push(["captcha", enc(cred.captcha)]);
	if (cred.sharkTicket) list.push(["shark_ticket", enc(cred.sharkTicket)]);
	list.push(["language", "zh"], ["multi_login", "1"], ["type", xor5Hex("24")], ["sec_sdk_version", "67765248"], ["account_sdk_source", "app"], ["passport_support_flow", "choose_account%2Ccaptcha%2Creal_name_check%2Cverify"], ["unbind_exist", xor5Hex("0")], ["verify_sdk_version", "4.2.1.cn"], ["is_from_iesaccountsaas", "1"]);
	return list.map(([k, v]) => `${k}=${v}`).join("&");
}
/** mobile/sms_login：code 与 mobile 都走 XOR */
function buildSmsLogin(code, mobileTicket, mobile) {
	return `is_vcd=1&safe_mobile_register_to_login=true&reg_cookie_opt=true&auth_opposite=1&ttnet_sdk_version=4.2.301.9-douyin&auth_sdk_version=4.7.7-rc.23&code=${xor5Hex(code)}&mobile_ticket=${enc(mobileTicket)}&mix_mode=1&account_app_language=zh&mobile=${xor5Hex(normalizeMobile(mobile))}&language=zh&user_api_need_combine=1&multi_login=1&sec_sdk_version=67765248&account_sdk_source=app&passport_support_flow=choose_account%2Ccaptcha%2Creal_name_check%2Cverify&verify_sdk_version=4.2.1.cn&is_from_iesaccountsaas=1&is_vcd_multi_account=1`;
}
/** user/login：密码登录入口（MFA 前后各调一次） */
function buildPwdLogin(mobile, password, opts = {}) {
	const list = [
		["mobile", xor5Hex(normalizeMobile(mobile))],
		["password", xor5Hex(password)],
		["mix_mode", "1"]
	];
	const d = opts.ctx;
	if (opts.captcha) list.push(["captcha", opts.captcha]);
	if (opts.sharkTicket) list.push(["shark_ticket", opts.sharkTicket]);
	if (d) {
		const ev = obj$1(d.event_params);
		const cp = obj$1(d.common_params);
		const way = opts.verifyWay ?? "mobile_sms_verify";
		list.push(["verify_way", way], ["std_verify_way", way], ["verify_scene", String(ev.verify_scene ?? cp.copywriting_key ?? "self_secondary_verify")]);
		if (opts.mobileTicket) list.push(["mobile_ticket", opts.mobileTicket]);
		if (d.encrypt_uid) list.push(["encrypt_uid", d.encrypt_uid]);
		if (d.not_login_ticket) list.push(["not_login_ticket", d.not_login_ticket]);
		for (const [k, v] of Object.entries(obj$1(d.biz_params))) if (v !== void 0 && v !== null && v !== "") list.push([k, String(v)]);
	}
	return pairs(list);
}
/** account/verify：密码二次验证（无 type / mobile_ticket / scene，三者自造会 1204） */
function buildVerify(d, password) {
	const ev = obj$1(d.event_params);
	const cp = obj$1(d.common_params);
	const scene = String(ev.verify_scene ?? cp.copywriting_key ?? "self_secondary_verify");
	const list = [
		["is_vcd", "1"],
		["reg_cookie_opt", "true"],
		["copywriting_key", String(cp.copywriting_key ?? scene)],
		["new_authn_sdk_version", "1.2.0-beta.1"],
		["ttnet_sdk_version", "4.2.301.9-douyin"],
		["auth_sdk_version", "4.7.7-rc.23"],
		["mix_mode", "1"],
		["account_app_language", "zh"],
		["verify_scene", scene],
		["language", "zh"],
		["multi_login", "1"],
		["encrypt_uid", d.encrypt_uid ?? ""],
		["verify_reason", String(ev.verify_reason ?? scene)],
		["sec_sdk_version", "67765248"],
		["password", xor5Hex(password)],
		["std_verify_way", "pwd_verify"],
		["account_sdk_source", "app"],
		["passport_support_flow", "choose_account,captcha,real_name_check,verify"],
		["verify_sdk_version", "4.2.1.cn"]
	];
	if (cp.ies_safety_diversion_tag) list.push(["ies_safety_diversion_tag", String(cp.ies_safety_diversion_tag)]);
	list.push(["is_from_iesaccountsaas", "1"], ["verify_way", "pwd_verify"]);
	return pairs(list);
}
/** MFA 公共表单：缺 $$secondVerificationRequestCommonParams 会 1204 */
function mfaForm(d, actType, extra = [], way = "mobile_sms_verify") {
	const ev = obj$1(d.event_params);
	const cp = obj$1(d.common_params);
	const scene = String(ev.verify_scene ?? cp.copywriting_key ?? "self_secondary_verify");
	const list = [
		["is_vcd", "1"],
		["reg_cookie_opt", "true"],
		["copywriting_key", cp.copywriting_key ?? scene],
		["new_authn_sdk_version", "1.2.0-beta.1"],
		["ttnet_sdk_version", "4.2.301.9-douyin"],
		["auth_sdk_version", "4.7.7-rc.23"],
		...extra,
		["mix_mode", "1"],
		["account_app_language", "zh"],
		["verify_scene", scene],
		["language", "zh"],
		["multi_login", "1"]
	];
	if (actType) list.push(["type", xor5Hex(actType)]);
	list.push(["encrypt_uid", d.encrypt_uid ?? ""], ["verify_reason", ev.verify_reason ?? scene], ["sec_sdk_version", "67765248"], ["std_verify_way", way], ["account_sdk_source", "app"], ["passport_support_flow", "choose_account,captcha,real_name_check,verify"], ["verify_sdk_version", "4.2.1.cn"]);
	if (cp.ies_safety_diversion_tag) list.push(["ies_safety_diversion_tag", cp.ies_safety_diversion_tag]);
	list.push(["is_from_iesaccountsaas", "1"], ["verify_way", way]);
	if (ev.std_verify_scene) list.push(["std_verify_scene", ev.std_verify_scene]);
	if (d.verify_ticket) list.push(["verify_ticket", d.verify_ticket]);
	return list;
}
/** MFA 下发短信：mobile/send_code（type=22，11 位裸号） */
function buildMfaSendCode(actType, d, mobile11 = "") {
	const extra = [];
	if (mobile11) extra.push(["mobile", mobile11]);
	extra.push(["is6Digits", "1"]);
	return pairs(mfaForm(d, actType, extra));
}
/** MFA 提交验证码：mobile/validate_code（type/code 走 XOR） */
function buildValidateCode(code, actType, d) {
	return pairs(mfaForm(d, actType, [["code", xor5Hex(code)]]));
}
/** 短信上行验证：upsms/verify；无 type/mobile，靠 x-tt-passport-mfa-token 关联 */
function buildUpSmsVerify(d) {
	return pairs(mfaForm(d, "", [], "mobile_up_sms_verify"));
}
/** MFA 扫码取码：mobile/get_qrcode（scene=secondary_verify） */
function buildMfaQrCodeBody(d, service) {
	return pairs(mfaForm(d, "", [
		["source", "app"],
		["scene", "secondary_verify"],
		["need_record", "1"],
		["service", service]
	], "qr_code_verify"));
}
/** MFA 扫码轮询：mobile/validate_by_qrcode（new → confirmed） */
function buildMfaQrCheckBody(token, d) {
	return pairs(mfaForm(d, "", [
		["token", token],
		["scene", "secondary_verify"],
		["need_record", "1"]
	], "qr_code_verify"));
}
/** 扫码登录取码 */
function buildQrCodeBody(service = "", source = "") {
	const list = [];
	if (service) list.push(["service", service]);
	list.push(["scene", "0"], ["need_logo", "1"], ["source", source], ["is_from_iesaccountsaas", "1"]);
	return pairs(list);
}
/** 扫码登录轮询：真机 CheckQrConnect 只带这五个字段，source/need_logo 属于取码阶段 */
function buildQrCheckBody(token, service = "aweme.snssdk.com") {
	return pairs([
		["token", token],
		["service", service],
		["scene", "0"],
		["user_api_need_combine", "1"],
		["is_from_iesaccountsaas", "1"]
	]);
}
/** MFA 通过后重放 check_qrconnect（body + biz_params + std_verify_way，不带 verify_ticket） */
function buildQrReplayBody(token, service, source, d, verifyTicket, mobileTicket = "", way = "mobile_sms_verify") {
	const ev = obj$1(d.event_params);
	const cp = obj$1(d.common_params);
	const scene = String(ev.verify_scene ?? cp.copywriting_key ?? "self_secondary_verify");
	const list = [
		["token", token],
		["service", service],
		["scene", "0"],
		["need_logo", "1"],
		["source", source],
		["is_from_iesaccountsaas", "1"],
		["verify_way", way],
		["std_verify_way", way],
		["verify_scene", scene]
	];
	if (verifyTicket) list.push(["verify_ticket", verifyTicket]);
	if (mobileTicket) list.push(["mobile_ticket", mobileTicket]);
	if (d.encrypt_uid) list.push(["encrypt_uid", d.encrypt_uid]);
	for (const [k, v] of Object.entries(obj$1(d.biz_params))) {
		if (v === void 0 || v === null || v === "") continue;
		list.push([k, k === "sms_code_key" ? xor5Hex(String(v)) : String(v)]);
	}
	return pairs(list);
}
/** 设置-保存登录信息：device_record_status/set（2 打开 / 1 关闭） */
function buildDeviceRecordStatus(status) {
	return pairs([
		["is_vcd", "1"],
		["reg_cookie_opt", "true"],
		["sec_sdk_version", "67765248"],
		["ttnet_sdk_version", "4.2.301.9-douyin"],
		["auth_sdk_version", "4.7.7-rc.23"],
		["account_sdk_source", "app"],
		["user_device_record_status", String(status)],
		["passport_support_flow", "choose_account,captcha,real_name_check,verify"],
		["account_app_language", "zh"],
		["verify_sdk_version", "4.2.1.cn"],
		["is_from_iesaccountsaas", "1"],
		["language", "zh"],
		["multi_login", "1"]
	]);
}
/** 登录成功后必调 update_token，否则 account/info 会 13（会话过期） */
function buildUpdateToken(dev, ids, t) {
	return pairs([
		["is_guest_mode", "0"],
		["manifest_version_code", dev.manifestVersionCode],
		["_rticket", t.rticket],
		["app_type", "normal"],
		["is_preinstall", "0"],
		["iid", ids.iid],
		["channel", dev.channel],
		["is_android_pad", "0"],
		["device_type", dev.deviceType],
		["language", "zh"],
		["cpu_support64", "true"],
		["host_abi", "arm64-v8a"],
		["resolution", dev.resolution.replace("x", "*")],
		["update_version_code", dev.updateVersionCode],
		["cdid", ids.cdid],
		["minor_status", "0"],
		["appTheme", dev.appTheme],
		["os_api", dev.osApi],
		["klink_egdi", ids.klink_egdi],
		["is_android_fold", "0"],
		["dpi", dev.dpi],
		["ac", dev.ac],
		["package", dev.packageName],
		["device_id", ids.device_id],
		["os", dev.os],
		["mcc_mnc", dev.mccMnc],
		["os_version", dev.osVersion],
		["version_code", dev.versionCode],
		["last_deeplink_update_version_code", "0"],
		["app_name", dev.appName],
		["version_name", dev.versionName],
		["push_sdk", "[10,15,21,26,27]"],
		["device_brand", dev.deviceBrand],
		["need_personal_recommend", "1"],
		["ssmix", dev.ssmix],
		["device_platform", dev.devicePlatform],
		["first_launch_timestamp", ids.first_install],
		["aid", dev.aid],
		["ts", t.ts]
	]);
}
/** NetworkProxyAccount：原参数 + biz_params + 额外参数（保序）；sms_code_key 走 XOR 并补 mix_mode */
function mergeBizParams(original, d, extra = {}) {
	const order = [];
	const m = /* @__PURE__ */ new Map();
	for (const [k, v] of new URLSearchParams(original)) {
		if (!m.has(k)) order.push(k);
		m.set(k, v);
	}
	for (const [k, v] of Object.entries(obj$1(d.biz_params))) {
		if (v === void 0 || v === null || v === "") continue;
		if (!m.has(k)) order.push(k);
		m.set(k, String(v));
	}
	for (const [k, v] of Object.entries(extra)) {
		if (!m.has(k)) order.push(k);
		m.set(k, v);
	}
	const smsKey = m.get("sms_code_key");
	if (smsKey) {
		m.set("sms_code_key", xor5Hex(smsKey));
		if (!m.has("mix_mode")) order.push("mix_mode");
		m.set("mix_mode", "1");
	}
	return order.map((k) => `${k}=${enc(m.get(k) ?? "")}`).join("&");
}
/** 服务端常把 params 传成 JSON 串 */
function obj$1(v) {
	if (!v) return {};
	if (typeof v === "string") try {
		return JSON.parse(v);
	} catch {
		return {};
	}
	return v;
}
//#endregion
//#region src/app/login.ts
/** 扫码接口固定参数（缺 service 会返回 error_code 3） */
const QR_SERVICE = "https://aweme.snssdk.com";
/**
* 登录入口用 s=-1：真机 hook 抄录与参考项目成功样例都是该值，此时服务端下发
* shark_admin 完整决策（带加密 detail）。s=0/2 只会下发 verify_center 的 10 字段
* 简化决策，没有 detail，滑块 verify 必然被判 5014。
*/
const TAG = "n=0;s=-1;p=0";
/** 滑块通过后的重发：真机只把 tag 升到 bdr-cnt=1 并补两个重试头，URL 与 body 完全不变 */
const RETRY = "bdr-cnt=1;n=0;s=-1;p=0";
/** 登录请求的入口标记；带 verify_ticket 说明是滑块通过后的重发 */
function entry(verifyTicket = "", extra = {}) {
	if (!verifyTicket) return {
		tag: TAG,
		extra
	};
	return {
		tag: RETRY,
		extra: {
			"x-tt-bdturing-retry": "1",
			"x-tt-passport-replay-params": "{}",
			...extra
		}
	};
}
var Login = class {
	auth;
	dev;
	ids;
	mobile;
	mobileTicket = "";
	last;
	lastData;
	/** 最近一次发出的 form（滑块重试 / MFA 重放基底） */
	lastBody = "";
	lastPath = "";
	/** 2046 原请求；MFA 辅助请求会覆盖 last，所以单独留一份 */
	pending;
	/** 是否存在待重放的 2046 原请求 */
	get waiting() {
		return Boolean(this.pending);
	}
	constructor(opts) {
		this.auth = opts.auth;
		this.dev = opts.dev;
		this.ids = opts.ids;
		this.mobile = opts.mobile ? normalizeMobile(opts.mobile) : "";
	}
	ctx() {
		return this.pending?.data ?? this.lastData ?? {};
	}
	async call(path, body, extra = {}) {
		const res = await send({
			auth: this.auth,
			dev: this.dev,
			ids: this.ids,
			path,
			body,
			...extra
		});
		this.last = res;
		this.lastPath = path;
		const data = parseData(res);
		this.lastData = data;
		if (data.mobile_ticket) this.mobileTicket = String(data.mobile_ticket);
		if (typeof body === "string") this.lastBody = body;
		if (Number(data.error_code) === 2046) this.pending = {
			path,
			body: typeof body === "string" ? body : "",
			data
		};
		return data;
	}
	/** 发送验证码（type=24；真机走 ttEncrypt+gzip，明文会被判旧客户端 1049） */
	sendCode(cred = {}) {
		return this.call("/passport/mobile/send_code/", buildSendCode(this.mobile, cred), {
			enc: "tt",
			...entry(cred.verifyTicket)
		});
	}
	/** 验证码登录；2046 表示进入二次验证 */
	smsLogin(code) {
		return this.call("/passport/mobile/sms_login/", buildSmsLogin(code, this.mobileTicket, this.mobile), entry());
	}
	/** 密码登录；1105 滑块通过后带 cred 重发 */
	pwdLogin(password, ctx, cred = {}) {
		return this.call("/passport/user/login/", buildPwdLogin(this.mobile, password, {
			ctx,
			...cred
		}), entry(cred.verifyTicket));
	}
	/** 密码二次验证（成功返回 ticket） */
	accountVerify(password) {
		this.auth.verifiedWay = "pwd_verify";
		return this.call("/passport/account/verify/", buildVerify(this.ctx(), password));
	}
	/** MFA 下发短信（type=22） */
	mfaSendCode(actType = "22", mobile11 = "") {
		return this.call("/passport/mobile/send_code/", buildMfaSendCode(actType, this.ctx(), mobile11), { enc: "plain" });
	}
	/** MFA 提交验证码（actType 见 verify_ways[].act_type） */
	validateCode(code, actType = "22") {
		this.auth.verifiedWay = "mobile_sms_verify";
		return this.call("/passport/mobile/validate_code/", buildValidateCode(code, actType, this.ctx()));
	}
	/** 上行短信验证：同一 body 轮询，手机发出短信后返回 registered=true */
	upSmsVerify() {
		this.auth.verifiedWay = "mobile_up_sms_verify";
		return this.call("/passport/upsms/verify/", buildUpSmsVerify(this.ctx()));
	}
	/** MFA 扫码取码（scene=secondary_verify，与登录码不同） */
	mfaQrGetCode(service = QR_SERVICE) {
		this.auth.verifiedWay = "qr_code_verify";
		return this.call("/passport/mobile/get_qrcode/", buildMfaQrCodeBody(this.ctx(), service), { extra: { "x-tt-app-id": String(this.dev.aid) } });
	}
	/** MFA 扫码轮询（new → confirmed） */
	mfaQrCheck(token) {
		this.auth.verifiedWay = "qr_code_verify";
		return this.call("/passport/mobile/validate_by_qrcode/", buildMfaQrCheckBody(token, this.ctx()), { extra: { "x-tt-app-id": String(this.dev.aid) } });
	}
	/**
	* 重放触发 2046 的原请求：原 body + biz_params + std_verify_way，不带 verify_ticket。
	* 验证结果由轮换的 x-tt-passport-mfa-token 关联。
	*/
	replayLogin(extra = {}) {
		const base = this.pending;
		if (base) {
			this.pending = void 0;
			if (base.path.includes("check_qrconnect")) {
				this.lastData = base.data;
				const p = new URLSearchParams(base.body);
				return this.qrReplay(p.get("token") ?? "", "", p.get("service") ?? "https://aweme.snssdk.com", p.get("source") ?? "pad");
			}
			const body = mergeBizParams(base.body, base.data, {
				std_verify_way: this.auth.verifiedWay || "mobile_sms_verify",
				...extra
			});
			return this.call(base.path, body);
		}
		if (!this.lastPath || !this.lastBody) throw new Error("没有待重放的请求");
		return this.call(this.lastPath, mergeBizParams(this.lastBody, {}, extra));
	}
	/** 登录成功后必调，否则 account/info 返回 13 */
	updateToken() {
		return this.call("/service/1/update_token/", buildUpdateToken(this.dev, this.ids, nowTime()));
	}
	accountInfo() {
		return this.call("/passport/account/info/v2/", null, { panel: "normal" });
	}
	record(status) {
		return this.call("/passport/user/device_record_status/set/", buildDeviceRecordStatus(status));
	}
	/** 扫码三接口必须带完整设备身份：缺 device_id/x-tt-dt 的会话轮询几轮后被判 2156 兜底 */
	qrGetCode(service = QR_SERVICE, source = "pad") {
		return this.call("/passport/mobile/get_qrcode/", buildQrCodeBody(service, source), {
			enc: "plain",
			...entry("", { "x-tt-app-id": String(this.dev.aid) })
		});
	}
	/** 真机 CheckQrConnect：POST，参数全在 query，载荷为空；service 不带 scheme */
	qrCheck(token, service = "aweme.snssdk.com") {
		const body = buildQrCheckBody(token, service);
		return this.call("/passport/mobile/check_qrconnect/", body, {
			enc: "plain",
			queryOnly: true,
			method: "POST",
			...entry("", { "x-tt-app-id": String(this.dev.aid) })
		});
	}
	qrReplay(token, verifyTicket = "", service = QR_SERVICE, source = "pad") {
		return this.call("/passport/mobile/check_qrconnect/", buildQrReplayBody(token, service, source, this.ctx(), verifyTicket, this.mobileTicket, this.auth.verifiedWay || "mobile_sms_verify"), {
			enc: "plain",
			...entry(verifyTicket, { "x-tt-app-id": String(this.dev.aid) })
		});
	}
};
function parseData(res) {
	return { ...(res.json ?? {}).data ?? {} };
}
//#endregion
//#region src/app/device.ts
/** 设备注册 + 激活：刷新失效设备凭据（passport 报 7 的系统繁忙多因凭据失效） */
/** 真机注册走 log.snssdk.com，激活走 klink；两者下发的设备级 cookie 不同 */
const REG_HOST = "https://log.snssdk.com";
const ACT_HOST = "https://klink.amemv.com";
const REG_PATH = "/service/2/device_register/";
const ACT_PATH = "/service/2/app_alert_check/";
/** 注册与登录必须共用同一套画像：服务端按 device_id 记住注册画像，登录时不一致会在扫码确认阶段判 7 */
const APP = {
	aid: String(DEV.aid),
	appName: DEV.appName,
	pkg: DEV.packageName,
	versionCode: String(DEV.versionCode),
	versionName: DEV.versionName,
	manifestVersionCode: String(DEV.manifestVersionCode),
	updateVersionCode: String(DEV.updateVersionCode),
	osVersion: DEV.osVersion,
	osApi: String(DEV.osApi),
	build: DEV.build,
	romVersion: DEV.romVersion,
	deviceType: DEV.deviceType,
	deviceBrand: DEV.deviceBrand,
	hostAbi: DEV.hostAbi,
	resolution: DEV.resolution,
	dpi: String(DEV.dpi),
	channel: DEV.channel,
	mccMnc: DEV.mccMnc
};
const UA = ua(DEV);
const SDK_VERSION = "3.7.3-rc.116-douyin";
/** APK 签名证书 MD5，同版本恒定 */
const SIG_HASH = "aea615ab910015038f73c47e45d21466";
/** 注册上报的装机时间必须与后续查询里的 first_launch_timestamp 完全一致 */
function regOf(ids) {
	const now = Math.floor(Date.now() / 1e3);
	return {
		openudid: ids.openudid,
		cdid: ids.cdid,
		clientudid: ids.clientudid,
		req_id: ids.req_id,
		oaid: ids.oaid,
		firstInstall: ids.first_install || now - 604800
	};
}
function traceId() {
	return `00-${randomUUID().replace(/-/g, "")}-${randomUUID().replace(/-/g, "").slice(0, 16)}-01`;
}
function regQuery(dev, ms) {
	const now = Math.floor(ms / 1e3);
	return [
		["ac", "wifi"],
		["channel", APP.channel],
		["aid", APP.aid],
		["app_name", APP.appName],
		["version_code", APP.versionCode],
		["version_name", APP.versionName],
		["device_platform", "android"],
		["os", "android"],
		["ssmix", "a"],
		["device_type", APP.deviceType],
		["device_brand", APP.deviceBrand],
		["language", "zh"],
		["os_api", APP.osApi],
		["os_version", APP.osVersion],
		["manifest_version_code", APP.manifestVersionCode],
		["resolution", APP.resolution],
		["dpi", APP.dpi],
		["update_version_code", APP.updateVersionCode],
		["_rticket", String(ms)],
		["package", APP.pkg],
		["mcc_mnc", APP.mccMnc],
		["first_launch_timestamp", String(dev.firstInstall)],
		["last_deeplink_update_version_code", "0"],
		["cpu_support64", "true"],
		["host_abi", APP.hostAbi],
		["is_guest_mode", "0"],
		["app_type", "normal"],
		["minor_status", "0"],
		["appTheme", "light"],
		["is_preinstall", "0"],
		["need_personal_recommend", "1"],
		["is_android_pad", "0"],
		["is_android_fold", "0"],
		["md", "0"],
		["cdid", dev.cdid],
		["cronet_version", "295fdb87_2026-08-31"],
		["ttnet_version", "4.2.301.9-douyin"],
		["use_store_region_cookie", "1"],
		["ts", String(now)]
	];
}
function actQuery(dev, ms) {
	const now = Math.floor(ms / 1e3);
	return [
		["aid", APP.aid],
		["app_name", APP.appName],
		["package", APP.pkg],
		["version_code", APP.versionCode],
		["version_name", APP.versionName],
		["manifest_version_code", APP.manifestVersionCode],
		["update_version_code", APP.updateVersionCode],
		["device_platform", "android"],
		["os", "android"],
		["ssmix", "a"],
		["ac", "wifi"],
		["channel", APP.channel],
		["device_type", APP.deviceType],
		["device_brand", APP.deviceBrand],
		["os_api", APP.osApi],
		["os_version", APP.osVersion],
		["language", "zh"],
		["resolution", APP.resolution],
		["dpi", APP.dpi],
		["openudid", dev.openudid],
		["cdid", dev.cdid],
		["clientudid", dev.clientudid],
		["cpu_support64", "true"],
		["host_abi", APP.hostAbi],
		["is_guest_mode", "0"],
		["app_type", "normal"],
		["minor_status", "0"],
		["appTheme", "light"],
		["is_preinstall", "0"],
		["need_personal_recommend", "1"],
		["is_android_pad", "0"],
		["is_android_fold", "0"],
		["timezone", "8"],
		["custom_bt", "1"],
		["req_id", dev.req_id],
		["ts", String(now)],
		["_rticket", String(ms)]
	];
}
/** ss_app_log 结构 */
function regBody(dev) {
	const now = Date.now();
	const header = {
		display_name: "抖音",
		update_version_code: Number(APP.updateVersionCode),
		manifest_version_code: Number(APP.manifestVersionCode),
		app_version_minor: "",
		aid: Number(APP.aid),
		channel: APP.channel,
		package: APP.pkg,
		app_version: APP.versionName,
		version_code: Number(APP.versionCode),
		sdk_version: SDK_VERSION,
		sdk_target_version: 29,
		git_hash: "fe95b95",
		os: "Android",
		os_version: APP.osVersion,
		os_api: Number(APP.osApi),
		device_model: APP.deviceType,
		device_brand: APP.deviceBrand,
		device_manufacturer: APP.deviceBrand,
		device_category: "phone",
		cpu_abi: APP.hostAbi,
		release_build: APP.build,
		density_dpi: Number(APP.dpi),
		display_density: "xxxhdpi",
		resolution: APP.resolution.split("*").reverse().join("x"),
		language: "zh",
		timezone: 8,
		access: "wifi",
		not_request_sender: 0,
		carrier: "",
		mcc_mnc: APP.mccMnc,
		rom: "V17.0.0",
		rom_version: APP.romVersion,
		cdid: dev.cdid,
		sig_hash: SIG_HASH,
		openudid: dev.openudid,
		clientudid: dev.clientudid,
		ipv6_list: [],
		region: "CN",
		tz_name: "Asia/Shanghai",
		tz_offset: 28800,
		sim_region: "cn",
		sim_serial_number: [],
		oaid: {
			req_id: randomUUID(),
			hw_id_version_code: "null",
			take_ms: "0",
			is_track_limited: "true",
			query_times: "1",
			id: dev.oaid,
			time: String(now)
		},
		oaid_may_support: true,
		req_id: dev.req_id,
		device_platform: "android",
		pre_installed_channel: "",
		apk_first_install_time: dev.firstInstall * 1e3,
		is_system_app: 0,
		sdk_flavor: "china",
		guest_mode: 0
	};
	return JSON.stringify({
		magic_tag: "ss_app_log",
		header,
		_gen_time: now
	});
}
function head(ms, stub, extra = []) {
	const list = [
		["content-type", "application/json; charset=utf-8"],
		["accept-encoding", "gzip, deflate, br"],
		["log-encode-type", "gzip"],
		["x-ss-dp", APP.aid],
		["x-tt-request-tag", "t=0;n=1;s=0;p=0"],
		["activity_now_client", String(ms)],
		["x-ss-req-ticket", String(ms)],
		["sdk-version", "2"],
		["passport-sdk-settings", "device_transfer_s_0,device_transfer_ab_0"],
		["passport-sdk-version", "60755"],
		["x-vc-bdturing-sdk-version", "4.2.1.cn"],
		["x-tt-trace-id", traceId()],
		["user-agent", UA]
	];
	if (stub) list.push(["x-ss-stub", stub]);
	return list.concat(extra);
}
function qs(list) {
	return list.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}
async function reg(base, opts) {
	const host = (opts.host ?? REG_HOST).replace(/\/$/, "");
	const dev = regOf(base);
	const sec = await boot(new Auth(), DEV, base);
	const ms = Date.now();
	const body = ttEncrypt(gzipSync(Buffer.from(regBody(dev), "utf8")));
	const url = `${host}${REG_PATH}?${qs([["tt_data", "a"], ...regQuery(dev, ms)])}`;
	const csrf = randomUUID().replace(/-/g, "");
	const headers = strip$1(head(ms, ssStub(body)).map(([k, v]) => k === "content-type" ? [k, "application/octet-stream;tt-data=a"] : [k, v]).concat([["cookie", `passport_csrf_token=${csrf}; passport_csrf_token_default=${csrf}`]]).concat(sec ? regHead(base, sec) : []));
	const sig = soSign(url, new Uint8Array(body));
	const res = await request({
		url,
		method: "POST",
		headers: [...headers, ...Object.entries(sig)],
		body,
		timeoutMs: opts.timeoutMs ?? 3e4
	});
	const d = res.json ?? {};
	const deviceId = String(d.device_id_str ?? "");
	if (!deviceId || deviceId === "0") throw new Error(`device_register 失败：${res.text.slice(0, 200) || "无响应"}`);
	const jar = new Jar();
	jar.merge(`passport_csrf_token=${csrf}; passport_csrf_token_default=${csrf}`);
	for (const line of res.setCookie) jar.absorb(line);
	const out = fill({
		...base,
		...dev,
		first_install: dev.firstInstall,
		device_id: deviceId,
		iid: String(d.install_id_str ?? ""),
		device_token: String(d.device_token ?? ""),
		device_id_str: deviceId,
		install_id_str: String(d.install_id_str ?? ""),
		new_user: Number(d.new_user ?? 0),
		klink_egdi: String(d.klink_egdi ?? base.klink_egdi),
		dtrait_pk1: String(d.dtrait_pk1 ?? base.dtrait_pk1 ?? ""),
		dtrait_pk2: String(d.dtrait_pk2 ?? base.dtrait_pk2 ?? ""),
		dtrait_pk1_version: String(d.dtrait_pk1_version ?? base.dtrait_pk1_version ?? ""),
		dtrait_pk2_version: String(d.dtrait_pk2_version ?? base.dtrait_pk2_version ?? ""),
		dtrait_token: String(d.dtrait_token ?? base.dtrait_token ?? ""),
		dtrait_version: Number(d.dtrait_version ?? base.dtrait_version ?? 0),
		bind_dtrait: d.bind_dtrait === void 0 ? base.bind_dtrait : d.bind_dtrait === true,
		source: "register",
		cookie: jar.header()
	});
	if (opts.activate !== false) await activate(out, opts);
	return out;
}
/** 激活：app_alert_check（tt_info = base64(ttEncrypt(gzip(query)))）；每次启动都要重新激活 */
async function activate(ids, opts = {}) {
	const host = (opts.host ?? ACT_HOST).replace(/\/$/, "");
	const dev = regOf(ids);
	const ms = Date.now();
	const ttInfo = ttEncrypt(gzipSync(Buffer.from(qs(actQuery(dev, ms)), "utf8"))).toString("base64");
	const url = `${host}${ACT_PATH}?aid=${APP.aid}&tt_info=${encodeURIComponent(ttInfo)}`;
	const headers = strip$1(head(ms, void 0, [["x-tt-dt", ids.device_token]])).filter(([k]) => k !== "content-type" && k !== "x-ss-dp");
	const sig = soSign(url, void 0, {
		deviceId: ids.device_id,
		installId: ids.iid
	});
	const res = await request({
		url,
		headers: [...headers, ...Object.entries(sig)],
		timeoutMs: opts.timeoutMs ?? 3e4
	});
	const msg = String(res.json?.message ?? "");
	return res.status === 200 && (res.headers["bd-tt-error-code"] === "0" || msg === "success");
}
/** 注册新设备并激活；返回可直接复用的 Ids（由调用方持久化） */
async function device(base, opts = {}) {
	return reg(fill(base), opts);
}
//#endregion
//#region src/app/keyhub.ts
/** keyhub 握手：ECDH(P-256) + HKDF 派生 IM/API 两把 ChaCha20 会话密钥 */
const URL$1 = "https://keyhub.zijieapi.com/handshake";
const APP_ID = "1128";
/** 4097 = secp256r1 + HKDF-SHA256 + ChaCha20 */
const SUITE = 4097;
/** info 是 16 字节 ASCII，不是 hex 解码后的 8 字节（运行时 hook 实证） */
const INFO_IM = Buffer.from("4e30514609050cd3", "utf8");
const INFO_API = Buffer.from("cab4ac74f61b5835", "utf8");
/** ChaCha20 (IETF)：加解密同一运算，iv = counter(4B) || nonce(12B) */
function chacha20(key, nonce, data) {
	if (nonce.length !== 12) throw new Error(`ChaCha20 nonce 必须 12 字节，实际 ${nonce.length}`);
	const c = createCipheriv("chacha20", key, Buffer.concat([Buffer.alloc(4), nonce]));
	return Buffer.concat([c.update(data), c.final()]);
}
/** 一次完整握手：生成 P-256 密钥对 → 签名 → POST → ECDH+HKDF */
async function handshake(deviceId, timeoutMs = 2e4) {
	if (!deviceId) throw new Error("keyhub 握手缺少 device_id");
	const ecdh = createECDH("prime256v1");
	ecdh.generateKeys();
	const pub = ecdh.getPublicKey();
	const clientRandom = randomBytes(32);
	const payload = Buffer.from(JSON.stringify({
		app_id: APP_ID,
		cipher_suites: [SUITE],
		did: deviceId,
		key_shares: [{
			curve: "secp256r1",
			pubkey: pub.toString("base64")
		}],
		random: clientRandom.toString("base64"),
		version: 2
	}), "utf8");
	const key = createPrivateKey({
		format: "jwk",
		key: {
			kty: "EC",
			crv: "P-256",
			d: ecdh.getPrivateKey().toString("base64url"),
			x: pub.subarray(1, 33).toString("base64url"),
			y: pub.subarray(33, 65).toString("base64url")
		}
	});
	const sig = sign("sha256", payload, key).toString("base64");
	const res = await request({
		url: URL$1,
		method: "POST",
		headers: [
			["content-type", "application/json"],
			["accept-encoding", "gzip, deflate, br"],
			["x-tt-request-tag", "n=0;s=0;p=0;ns=0;ff=0;mp=0"],
			["x-tt-s-sign", sig],
			["user-agent", ua(DEV)]
		],
		body: payload,
		timeoutMs
	});
	if (res.status !== 200) throw new Error(`keyhub 握手失败 HTTP ${res.status}: ${res.text.slice(0, 200)}`);
	const j = res.json;
	if (!j?.ticket || !j.key_share?.pubkey || !j.random) throw new Error(`keyhub 响应缺字段: ${res.text.slice(0, 200)}`);
	const shared = ecdh.computeSecret(Buffer.from(j.key_share.pubkey, "base64"));
	const salt = Buffer.concat([clientRandom, Buffer.from(j.random, "base64")]);
	const now = Date.now();
	return {
		ticket: j.ticket,
		ticketLong: j.ticket_long,
		keyIM: Buffer.from(hkdfSync("sha256", shared, salt, INFO_IM, 32)),
		keyAPI: Buffer.from(hkdfSync("sha256", shared, salt, INFO_API, 32)),
		issuedAt: now,
		expiresAt: now + (j.ticket_exp && j.ticket_exp > 0 ? j.ticket_exp : 10800) * 1e3,
		deviceId
	};
}
//#endregion
//#region src/app/rest.ts
/** form 体里数组按 JSON 串写入，与真机 show_group_list=[...] 的形态一致 */
function form$1(body) {
	const q = new URLSearchParams();
	for (const [k, v] of Object.entries(body)) {
		if (v === void 0) continue;
		q.append(k, typeof v === "string" ? v : JSON.stringify(v));
	}
	return q.toString();
}
async function rest(im, path, opts = {}) {
	const enc = opts.enc ?? (opts.body === void 0 ? "none" : "json");
	const body = opts.body === void 0 ? void 0 : typeof opts.body === "string" ? opts.body : enc === "form" || enc === "zstd-form" ? form$1(opts.body) : JSON.stringify(opts.body);
	const res = await im.call({
		path,
		host: opts.host,
		method: opts.method ?? (body === void 0 ? "GET" : "POST"),
		enc,
		query: opts.query,
		body
	});
	if (res.json !== void 0) return res.json;
	if (!res.text.trim()) return {};
	throw new Error(`${path} 非 JSON 响应 status=${res.status}`);
}
/** 常用业务 host，抓包中同一 path 可能在多个域下命中 */
const DOMAIN = {
	core: "api5-core-jj.amemv.com",
	social: "api5-social-m-jj.amemv.com",
	socialLf: "api5-social-m-lf.amemv.com",
	normal: "api5-normal-lf.amemv.com",
	normalM: "api5-normal-m-jj.amemv.com",
	normal3: "api3-normal-c.amemv.com",
	platform: "api5-platform-lf.amemv.com",
	platformM: "api5-platform-m-jj.amemv.com"
};
/**
* path 以真机抓包为准：会话/消息/已读三个 pb 接口不带 /aweme 前缀，
* enter_chat 与 active/status 带尾斜杠；前缀不对会命中网关兜底路由（200 空 body / 3105）。
*/
const IM_ENDPOINTS = {
	conversationInfo: {
		path: "/v2/conversation/get_info",
		method: "POST",
		enc: "pb"
	},
	conversationInfoList: {
		path: "/v2/conversation/get_info_list",
		method: "POST",
		enc: "pb",
		host: "api5-social-m-lf.amemv.com"
	},
	markRead: {
		path: "/v3/conversation/mark_read",
		method: "POST",
		enc: "pb"
	},
	getByConversation: {
		path: "/v1/message/get_by_conversation",
		method: "POST",
		enc: "pb"
	},
	userMessage: {
		path: "/v3/message/get_user_message",
		method: "POST",
		enc: "pb"
	},
	enterChat: {
		path: "/aweme/v1/im/service/enter_chat/",
		method: "POST",
		enc: "zstd-json"
	},
	activeStatus: {
		path: "/aweme/v1/im/user/active/status/",
		method: "POST",
		enc: "form"
	},
	groupOnline: {
		path: "/aweme/v1/im/user/group/online",
		method: "GET",
		enc: "none"
	},
	bulletEvent: {
		path: "/aweme/v1/im/bullet/common_event/request_and_update",
		method: "POST",
		enc: "json"
	},
	groupEntryLimit: {
		path: "/aweme/v1/im/group/settings/entry_limit",
		method: "GET",
		enc: "none"
	},
	otherScene: {
		path: "/aweme/v2/im/conversation/info/other/scene",
		method: "GET",
		enc: "none"
	},
	otherInfo: {
		path: "/aweme/v1/im/conversation/info/other",
		method: "POST",
		enc: "form"
	},
	floatingBarCheck: {
		path: "/aweme/v1/im/conversation/floating_bar/check",
		method: "GET",
		enc: "none"
	},
	floatingBarConfigs: {
		path: "/aweme/v1/im/conversation/floating_bar/configs",
		method: "GET",
		enc: "none"
	},
	emoticonSearch: {
		path: "/aweme/v1/im/resources/emoticon/search",
		method: "GET",
		enc: "none"
	},
	hellosticker: {
		path: "/aweme/v1/im/hellosticker",
		method: "GET",
		enc: "none"
	},
	imageUpload: {
		path: "/aweme/v1/im/image/upload",
		method: "POST",
		enc: "pb"
	}
};
function base(dev, ids) {
	const list = [
		["x-tt-multi-sids", "none"],
		["sdk-version", "2"],
		["x-ss-dp", String(dev.aid)],
		["x-tt-request-tag", "n=0;s=-1;p=0"],
		["x-vc-bdturing-sdk-version", "4.2.1.cn"],
		["x-tt-dt", ids.device_token],
		["user-agent", ua(dev)]
	];
	if (ids.device_dtrait) list.splice(2, 0, ["x-tt-device-dtrait", ids.device_dtrait]);
	if (ids.device_dtrait_token) list.splice(2, 0, ["x-tt-device-dtrait-token", ids.device_dtrait_token]);
	if (ids.client_key) list.push(["x-bd-client-key", ids.client_key]);
	return list;
}
function find$1(pairs, name) {
	const ln = name.toLowerCase();
	for (let i = pairs.length - 1; i >= 0; i--) if (pairs[i][0].toLowerCase() === ln) return pairs[i][1];
}
function put(pairs, name, value) {
	const ln = name.toLowerCase();
	const i = pairs.findIndex(([n]) => n.toLowerCase() === ln);
	if (i >= 0) pairs[i] = [pairs[i][0], value];
	else pairs.push([name, value]);
}
var Im = class {
	dev;
	ids;
	auth;
	tk;
	id;
	session;
	constructor(opts) {
		this.dev = opts.dev;
		this.ids = opts.ids;
		this.auth = opts.auth;
	}
	/** 取未临近过期的 IM 会话（首次触发 keyhub 握手） */
	async key(force = false) {
		if (!force && this.session && this.session.deviceId === this.ids.device_id && Date.now() < this.session.expiresAt - 3e5) return this.session;
		this.session = await handshake(this.ids.device_id);
		return this.session;
	}
	/** 信封 token：真机取 fetchMixInit 下发的 im_token，取不到退化用 sessionid */
	async token() {
		if (this.tk) return this.tk;
		try {
			const t = (await this.call({
				path: "/aweme/v1/im/reboot/misc/",
				method: "GET"
			})).json?.im_token;
			if (typeof t === "string" && t) this.tk = t;
		} catch {}
		this.tk ??= String(this.auth.jar.get("sessionid") ?? "");
		return this.tk;
	}
	/** 登录 uid：x-tt-e-k 必须是 uid+IM，cookie 里没有，只能从自身资料取一次 */
	async uid() {
		if (this.id) return this.id;
		try {
			const u = (await this.call({
				path: "/aweme/v1/user/profile/self/",
				host: DOMAIN.core,
				method: "GET"
			})).json?.user?.uid;
			if (u != null) this.id = String(u);
		} catch {}
		return this.id ?? String(this.auth.jar.get("uid") ?? "");
	}
	async call(call = {}) {
		const ep = call.name ? IM_ENDPOINTS[call.name] : void 0;
		const enc = call.enc ?? ep?.enc ?? (call.body ? "pb" : "none");
		const method = call.method ?? ep?.method ?? (call.body ? "POST" : "GET");
		const q = socialQuery(this.dev, this.ids, call.query);
		const url = buildUrl(call.host ?? ep?.host ?? "api5-social-m-jj.amemv.com", call.path ?? ep?.path ?? "/", q, {});
		const pairs = strip$1(base(this.dev, this.ids));
		const cookie = this.auth.cookie();
		if (cookie) pairs.push(["cookie", cookie]);
		for (const n of ["x-tt-token", "x-tt-token-supplement"]) {
			const v = this.auth.tokens[n];
			if (v) pairs.push([n, v]);
		}
		for (const [k, v] of Object.entries(call.headers ?? {})) put(pairs, k.toLowerCase(), v);
		let payload;
		let text;
		let sbytes;
		let keyIM;
		if (call.body !== void 0) {
			const body = Buffer.isBuffer(call.body) ? call.body : Buffer.from(call.body, "utf8");
			if (enc === "pb") {
				payload = body;
				put(pairs, "content-type", "application/x-protobuf");
				if (call.encrypt !== false) {
					const sess = call.session ?? await this.key();
					keyIM = sess.keyIM;
					const nonce = Buffer.from(find$1(pairs, "x-tt-e-p") ?? "", "base64");
					const use = nonce.length === 12 ? nonce : randomBytes(12);
					payload = chacha20(keyIM, use, body);
					put(pairs, "x-tt-e-b", "1");
					put(pairs, "x-tt-e-p", use.toString("base64"));
					put(pairs, "x-tt-e-t", find$1(pairs, "x-tt-e-t") ?? sess.ticket);
					put(pairs, "x-ss-stub", ssStub(body));
					const uid = await this.uid();
					if (uid) put(pairs, "x-tt-e-k", `${uid}+IM`);
					sbytes = payload;
				} else sbytes = payload;
			} else if (enc === "zstd-json" || enc === "zstd-form") {
				payload = zstdCompress(body);
				text = body.toString("utf8");
				put(pairs, "content-type", enc === "zstd-json" ? "application/json" : "application/x-www-form-urlencoded");
				put(pairs, "x-bd-content-encoding", "zstd");
				put(pairs, "x-ss-stub", ssStub(body));
			} else {
				payload = body;
				text = body.toString("utf8");
				put(pairs, "content-type", enc === "json" ? "application/json" : "application/x-www-form-urlencoded");
				if (enc === "form" || enc === "json") put(pairs, "x-ss-stub", ssStub(body));
			}
			put(pairs, "content-length", String(payload.length));
		}
		put(pairs, "accept-encoding", "gzip, deflate, br");
		const sig = sign$1({
			url,
			headers: pairs,
			body: text,
			bodyBytes: sbytes,
			deviceIds: { deviceId: this.ids.device_id }
		});
		for (const [k, v] of Object.entries(sig)) pairs.push([k, v]);
		const res = await request({
			url,
			method,
			headers: pairs,
			body: payload,
			timeoutMs: call.timeoutMs
		});
		this.auth.absorb(res.setCookie);
		return decode(res, keyIM);
	}
};
function decode(res, key) {
	let raw = res.body;
	let ready = true;
	const nonce = res.headers["x-tt-e-p"];
	if (key && nonce && raw.length > 0 && res.status === 200) try {
		raw = chacha20(key, Buffer.from(nonce, "base64"), raw);
	} catch {
		ready = false;
	}
	else if (nonce && raw.length > 0 && res.status === 200) ready = false;
	const text = raw.toString("utf8");
	const ct = res.headers["content-type"] ?? "";
	let json;
	if (ct.includes("json") || /^[{\[]/.test(text.trimStart())) try {
		json = JSON.parse(text);
	} catch {
		json = void 0;
	}
	return {
		status: res.status,
		headers: res.headers,
		raw,
		text,
		json,
		ready
	};
}
//#endregion
//#region src/app/ee.ts
/** ee.info 通道：96B key 包 (A16 || M48 || B32) 的密封/解封，与 keyhub HKDF 是两条独立链路 */
const SEED = pbkdf2Sync("TokenManager", "0x801020", 1001, 16, "sha1");
const EE_KA = pbkdf2Sync("ee.info", SEED, 1003, 16, "sha1");
const EE_KH = pbkdf2Sync("ee.info", SEED, 1004, 16, "sha1");
/** 把已配对的 32B key 封成 96B 包；凭空造 key 服务端会拒 */
function packEeKey(chachaKey, A = randomBytes(16)) {
	if (chachaKey.length !== 32) throw new Error(`chachaKey 应为 32B，实际 ${chachaKey.length}B`);
	if (A.length !== 16) throw new Error(`A 应为 16B，实际 ${A.length}B`);
	const c = createCipheriv("aes-128-cbc", EE_KA, A);
	const M = Buffer.concat([c.update(chachaKey), c.final()]);
	const B = createHmac("sha256", EE_KH).update(Buffer.concat([A, M])).digest();
	return Buffer.concat([
		A,
		M,
		B
	]).toString("base64");
}
/** keyhub 会话 → ee.info 条目（id 形如 `<uid>+IM`） */
function eeEntry(sess, id) {
	return {
		id,
		type: 1,
		key: packEeKey(sess.keyIM),
		ticket: sess.ticket,
		expire: sess.expiresAt / 1e3
	};
}
//#endregion
//#region src/app/captcha.ts
function obj(v) {
	return v && typeof v === "object" ? v : {};
}
/** 优先响应头，其次 body 的 verify_center_decision_conf */
function read(res) {
	if (!res) return void 0;
	const data = obj(obj(res.json)["data"]);
	let decision = {};
	const header = res.headers["bdturing-verify"];
	if (header) try {
		decision = obj(JSON.parse(header));
	} catch {}
	if (Object.keys(decision).length === 0) {
		const conf = data["verify_center_decision_conf"];
		if (typeof conf === "string") try {
			decision = obj(JSON.parse(conf));
		} catch {
			return;
		}
	}
	const verifyTicket = String(decision["verify_ticket"] ?? data["verify_ticket"] ?? "");
	if (!verifyTicket && !decision["detail"]) return void 0;
	return {
		verifyTicket,
		decision,
		raw: header ?? JSON.stringify(decision),
		params: res.headers["x-vc-bdturing-parameters"] ?? "",
		subtype: String(decision["subtype"] ?? ""),
		verifyEvent: String(decision["verify_event"] ?? ""),
		logId: String(decision["log_id"] ?? res.headers["x-tt-logid"] ?? ""),
		at: Date.now()
	};
}
//#endregion
//#region src/app/auto.ts
/** 滑块自动通过：用 decision 声明的真机形态跑官方 SDK；桌面/手机浏览器形态与 App 通道矛盾会 5014 */
const log$2 = createLog({ tag: "auto" });
/** DY_DUMP_GAP 落图序号：一进程多题时会话并存，固定文件名会互相覆盖 */
let dumpN = 0;
/** 载荷落盘序号，同样按进程递增避免覆盖 */
let payN = 0;
/** 排查用：SDK 把明文 JSON 交给加密函数，钩住 stringify 就能看到它采集了哪些 env 与轨迹 */
const PAYLOAD_HOOK = `globalThis.__SJ = []; (() => {
  const s = JSON.stringify, out = globalThis.__SJ;
  JSON.stringify = function () {
    const r = s.apply(this, arguments);
    try { if (typeof r === 'string' && r.length > 500) out.push(r) } catch (e) {}
    return r;
  };
})();`;
function dumpDir() {
	const d = process.env.DY_DUMP_GAP;
	return d && d !== "1" ? d : join(tmpdir(), "dy-gap");
}
async function dumpPayload(page) {
	const list = await page.evaluate(() => globalThis.__SJ ?? []).catch(() => []);
	if (!list.length) {
		log$2.warn("没拿到载荷：SDK 未走 JSON.stringify");
		return;
	}
	const dir = dumpDir();
	mkdirSync(dir, { recursive: true });
	const no = ++payN;
	list.forEach((s, i) => writeFileSync(join(dir, `payload-${no}-${i}.json`), s));
	log$2.info(`载荷已落盘 ${list.length} 条 → ${dir}`);
}
function sleep$2(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
* 设备 resolution + dpi → 浏览器视口与 DPR。
* 必须用注册时上报的分辨率：滑块通道若声明另一套整屏尺寸，与登录/注册参数矛盾会被判 5014。
*/
function viewport(dev) {
	const m = /^(\d+)\s*[*x]\s*(\d+)$/i.exec(dev.resolution);
	const dpr = Math.max(1, dev.dpi / 160);
	const w = m ? Number(m[1]) : 1272;
	const h = m ? Number(m[2]) : 2800;
	return {
		width: Math.max(320, Math.min(480, Math.round(w / dpr))),
		height: Math.max(560, Math.min(900, Math.round(h / dpr))),
		dpr: Math.round(dpr * 100) / 100
	};
}
/** 必须是带 wv 的 Android WebView 形态：无 wv 的普通手机/桌面浏览器一律被 bdturing 判 5014 */
function webViewUa(dev) {
	return `Mozilla/5.0 (Linux; Android ${dev.osVersion}; ${dev.deviceType} Build/${dev.build}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36`;
}
async function launch(pw, dev) {
	const vp = viewport(dev);
	const headless = process.env.DY_SLIDE_HEADLESS === "1";
	for (const channel of [
		"msedge",
		"chrome",
		void 0
	]) try {
		const browser = await pw.chromium.launch({
			channel,
			headless,
			args: ["--disable-blink-features=AutomationControlled", `--window-size=${vp.width},${vp.height}`]
		});
		log$2.info(`浏览器已启动（${channel ?? "自带 chromium"}，headless=${headless}）`);
		return browser;
	} catch (e) {
		log$2.warn(`启动 ${channel ?? "chromium"} 失败: ${String(e).slice(0, 140)}`);
	}
	return null;
}
/**
* 拟人横向位移序列：真机触摸约 60Hz 采样、整段 0.8~1.5s，点数 50+。
* 点太少太快（原来 20~30 点/300ms）会被 bdturing 判成机器，直接回 5014。
*/
function humanTrack(dx) {
	const steps = 52 + Math.floor(Math.random() * 38);
	const track = [];
	const over = Math.random() < .7 ? 1 + Math.random() * 2.5 : 0;
	const total = dx + over;
	let cur = 0;
	for (let i = 1; i <= steps; i++) {
		const p = i / steps;
		const target = total * (1 - Math.pow(1 - p, 3));
		const jitter = (Math.random() * 2 - 1) * (p < .9 ? .9 : .25);
		const next = Math.max(cur, target + jitter);
		if (next - cur < .5) continue;
		track.push(Number((next - cur).toFixed(2)));
		cur = next;
	}
	if (over > 0) {
		track.push(Number((-over).toFixed(2)));
		cur -= over;
	}
	track.push(Number((dx - cur).toFixed(2)));
	return track;
}
/** 返回首个真值结果；超时为 null。用返回值而非闭包赋值，避免 TS 认为外部变量恒为初始值 */
async function waitFor(probe, timeoutMs, step = 200) {
	const end = Date.now() + timeoutMs;
	while (Date.now() < end) {
		try {
			const v = await probe();
			if (v) return v;
		} catch {}
		await sleep$2(step);
	}
	return null;
}
/** 读滑块几何：拖动前必须现量，SDK 的入场动画会让几秒前的 rect 失效 */
function geo(page) {
	return page.evaluate(() => {
		const doc = globalThis.document;
		const bg = doc.querySelector(".captcha-verify-image");
		const pc = doc.querySelector("#captcha-verify_img_slide");
		const btn = doc.querySelector(".captcha-slider-btn");
		if (!bg || !pc || !btn) return null;
		const r1 = bg.getBoundingClientRect();
		const r2 = pc.getBoundingClientRect();
		const r3 = btn.getBoundingClientRect();
		return {
			bgW: Math.round(r1.width),
			bgH: Math.round(r1.height),
			pcW: Math.round(r2.width),
			pcH: Math.round(r2.height),
			pieceOffX: r2.x - r1.x,
			pieceOffY: r2.y - r1.y,
			btnX: r3.x + r3.width / 2,
			btnY: r3.y + r3.height / 2
		};
	});
}
/**
* 页面内模板匹配：灰度零均值 NCC。
* 必须在原图分辨率上算——显示尺寸把 552 缩到 363 后，真缺口与旁边假缺口的分数差会被抹平。
* 几何依据：移动端 .verify-image 宽 2.76em、拼图 0.55em，拼图纵向位置 = tip_y/100 em，
* 换算回原图坐标就是 tip_y*bgNatW/276。
*/
async function matchFn(a) {
	const g = globalThis;
	const doc = g.document;
	const load = async (b64) => {
		const bin = g.atob(b64);
		const u8 = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
		const bmp = await g.createImageBitmap(new g.Blob([u8]));
		const cv = doc.createElement("canvas");
		cv.width = bmp.width;
		cv.height = bmp.height;
		const c2 = cv.getContext("2d", { willReadFrequently: true });
		if (!c2) throw new Error("canvas 2d 不可用");
		c2.drawImage(bmp, 0, 0);
		return {
			w: cv.width,
			h: cv.height,
			d: c2.getImageData(0, 0, cv.width, cv.height).data
		};
	};
	const bg = await load(a.bgB64);
	const pc = await load(a.pcB64);
	const BW = bg.w;
	const BH = bg.h;
	const PW = pc.w;
	const PH = pc.h;
	if (PW > BW || PH > BH) return {
		drag: 0,
		score: -1,
		error: "拼图比背景大"
	};
	let note;
	const pGray = new Float32Array(PW * PH);
	let minX = PW;
	let maxX = -1;
	let minY = PH;
	let maxY = -1;
	for (let y = 0; y < PH; y++) for (let x = 0; x < PW; x++) {
		const i = (y * PW + x) * 4;
		pGray[y * PW + x] = .299 * pc.d[i] + .587 * pc.d[i + 1] + .114 * pc.d[i + 2];
		if (pc.d[i + 3] > 40) {
			if (x < minX) minX = x;
			if (x > maxX) maxX = x;
			if (y < minY) minY = y;
			if (y > maxY) maxY = y;
		}
	}
	if (maxX < 0) return {
		drag: 0,
		score: -1,
		error: "拼图 alpha 为空"
	};
	const oxs = [];
	const oys = [];
	for (let y = minY; y <= maxY; y++) for (let x = minX; x <= maxX; x++) {
		if (pc.d[(y * PW + x) * 4 + 3] <= 40) continue;
		oxs.push(x);
		oys.push(y);
	}
	const n = oxs.length;
	const maskW = maxX - minX + 1;
	const maskH = maxY - minY + 1;
	const dark = new Uint8Array(BW * BH);
	for (let j = 0, i = 0; j < dark.length; j++, i += 4) {
		const r = bg.d[i];
		const g2 = bg.d[i + 1];
		const b2 = bg.d[i + 2];
		const mx = r > g2 ? r > b2 ? r : b2 : g2 > b2 ? g2 : b2;
		if (mx < 135 && mx - (r < g2 ? r < b2 ? r : b2 : g2 < b2 ? g2 : b2) < 95) dark[j] = 1;
	}
	const bGray = new Float32Array(BW * BH);
	for (let j = 0, i = 0; j < bGray.length; j++, i += 4) bGray[j] = .299 * bg.d[i] + .587 * bg.d[i + 1] + .114 * bg.d[i + 2];
	const makeScorer = (step) => {
		const idx = [];
		for (let k = 0; k < n; k += step) idx.push(k);
		let s0 = 0;
		for (const k of idx) s0 += pGray[oys[k] * PW + oxs[k]];
		const m0 = s0 / idx.length;
		const v0 = new Float64Array(idx.length);
		let n0 = 0;
		for (let j = 0; j < idx.length; j++) {
			const v = pGray[oys[idx[j]] * PW + oxs[idx[j]]] - m0;
			v0[j] = v;
			n0 += v * v;
		}
		n0 = Math.sqrt(n0) || 1;
		return (x, y) => {
			let sum = 0;
			let sum2 = 0;
			for (let j = 0; j < idx.length; j++) {
				const v = bGray[(y + oys[idx[j]]) * BW + (x + oxs[idx[j]])];
				sum += v;
				sum2 += v * v;
			}
			const cnt = idx.length;
			const mean = sum / cnt;
			const varB = sum2 - cnt * mean * mean;
			if (varB <= .001) return -2;
			let dot = 0;
			for (let j = 0; j < idx.length; j++) dot += v0[j] * (bGray[(y + oys[idx[j]]) * BW + (x + oxs[idx[j]])] - mean);
			return dot / (n0 * Math.sqrt(varB));
		};
	};
	const nccOf = makeScorer(2);
	const W1 = BW + 1;
	const ss = new Float64Array(W1 * (BH + 1));
	const sq = new Float64Array(W1 * (BH + 1));
	const sd = new Int32Array(W1 * (BH + 1));
	for (let y = 0; y < BH; y++) {
		let row = 0;
		let row2 = 0;
		let rowd = 0;
		for (let x = 0; x < BW; x++) {
			const v = bGray[y * BW + x];
			row += v;
			row2 += v * v;
			rowd += dark[y * BW + x];
			ss[(y + 1) * W1 + (x + 1)] = ss[y * W1 + (x + 1)] + row;
			sq[(y + 1) * W1 + (x + 1)] = sq[y * W1 + (x + 1)] + row2;
			sd[(y + 1) * W1 + (x + 1)] = sd[y * W1 + (x + 1)] + rowd;
		}
	}
	const area = (p, x, y) => p[(y + maskH) * W1 + x + maskW] - p[y * W1 + x + maskW] - p[(y + maskH) * W1 + x] + p[y * W1 + x];
	const sample = [];
	for (let k = 0; k < n; k += 3) sample.push(k);
	const cnt = maskW * maskH;
	/** 拼图内容 bbox 落在 (bx,by) 时与暗块的重合度；0 表示该位置不可能 */
	const shape = (bx, by) => {
		const wd = area(sd, bx, by);
		if (wd < n * .5 || wd > n * 2.4) return 0;
		const mean = area(ss, bx, by) / cnt;
		if (mean > 130) return 0;
		const flat = 1 - Math.sqrt(Math.max(0, area(sq, bx, by) / cnt - mean * mean)) / 18;
		if (flat <= 0) return 0;
		let hit = 0;
		for (const k of sample) if (dark[(by + oys[k] - minY) * BW + bx + oxs[k] - minX]) hit++;
		const inter = hit * n / sample.length;
		return inter / (n + wd - inter) * flat;
	};
	const kh = 20;
	const diff = new Float32Array(BW * BH);
	for (let y = 0; y < BH; y++) {
		const ya = Math.max(0, y - kh);
		const yb = Math.min(BH, y + kh + 1);
		for (let x = 0; x < BW; x++) {
			const xa = Math.max(0, x - kh);
			const xb = Math.min(BW, x + kh + 1);
			const s = ss[yb * W1 + xb] - ss[ya * W1 + xb] - ss[yb * W1 + xa] + ss[ya * W1 + xa];
			diff[y * BW + x] = s / ((yb - ya) * (xb - xa)) - bGray[y * BW + x];
		}
	}
	const dOff = [];
	for (let k = 0; k < n; k += 3) dOff.push(oys[k] * BW + oxs[k]);
	const dN = dOff.length;
	const darkMean = (x, y) => {
		const base = y * BW + x;
		let sum = 0;
		for (let j = 0; j < dN; j++) sum += diff[base + dOff[j]];
		return sum / dN;
	};
	const cand = [];
	for (let y = 0; y + PH <= BH; y += 4) for (let x = 0; x + PW <= BW; x += 4) cand.push([
		x,
		y,
		darkMean(x, y)
	]);
	cand.sort((p, q) => q[2] - p[2]);
	let dBest = -1e9;
	let d2 = -1e9;
	let dX = 0;
	let dY = 0;
	for (const [x, y, v] of cand) if (dBest < -1e8) {
		dBest = v;
		dX = x;
		dY = y;
	} else if (Math.abs(x - dX) > 40 || Math.abs(y - dY) > 40) {
		d2 = v;
		break;
	}
	if (dBest < -1e8) return {
		drag: 0,
		score: -1,
		error: "暗剪影无候选"
	};
	const dOffF = [];
	for (let k = 0; k < n; k++) dOffF.push(oys[k] * BW + oxs[k]);
	const darkFull = (x, y) => {
		const base = y * BW + x;
		let sum = 0;
		for (let j = 0; j < dOffF.length; j++) sum += diff[base + dOffF[j]];
		return sum / dOffF.length;
	};
	for (let y = Math.max(0, dY - 12); y <= Math.min(BH - PH, dY + 12); y++) for (let x = Math.max(0, dX - 12); x <= Math.min(BW - PW, dX + 12); x++) {
		const v = darkFull(x, y);
		if (v > dBest) {
			dBest = v;
			dX = x;
			dY = y;
		}
	}
	if (dBest > 6 && dBest > d2 * 1.35) return {
		drag: dX * (a.bgW / BW) - a.pieceOffX,
		score: dBest,
		gapLeft: dX * (a.bgW / BW),
		gapTop: dY,
		bgNatW: BW,
		pcNat: PW,
		dark: dBest,
		second: d2,
		top: [[
			dX,
			dY,
			dBest
		]]
	};
	const seen = new Uint8Array(BW * BH);
	const cells = [];
	const hits = [];
	for (let s = 0; s < dark.length; s++) {
		if (!dark[s] || seen[s]) continue;
		cells.length = 0;
		seen[s] = 1;
		cells.push(s);
		let cx0 = BW;
		let cx1 = -1;
		let cy0 = BH;
		let cy1 = -1;
		for (let h = 0; h < cells.length; h++) {
			const p = cells[h];
			const x = p % BW;
			const y = Math.floor(p / BW);
			if (x < cx0) cx0 = x;
			if (x > cx1) cx1 = x;
			if (y < cy0) cy0 = y;
			if (y > cy1) cy1 = y;
			if (x > 0 && dark[p - 1] && !seen[p - 1]) {
				seen[p - 1] = 1;
				cells.push(p - 1);
			}
			if (x + 1 < BW && dark[p + 1] && !seen[p + 1]) {
				seen[p + 1] = 1;
				cells.push(p + 1);
			}
			if (p >= BW && dark[p - BW] && !seen[p - BW]) {
				seen[p - BW] = 1;
				cells.push(p - BW);
			}
			if (p + BW < dark.length && dark[p + BW] && !seen[p + BW]) {
				seen[p + BW] = 1;
				cells.push(p + BW);
			}
		}
		const cw = cx1 - cx0 + 1;
		const ch = cy1 - cy0 + 1;
		if (cells.length < n * .15) continue;
		if (cw < maskW * .45 || cw > maskW * 3.2 || ch < maskH * .45 || ch > maskH * 3.2) continue;
		const xa = Math.max(0, cx0 - maskW + 1);
		const xb = Math.min(BW - maskW, cx1);
		const ya = Math.max(0, cy0 - maskH + 1);
		const yb = Math.min(BH - maskH, cy1);
		let best = 0;
		let bx0 = xa;
		let by0 = ya;
		for (let by = ya; by <= yb; by += 3) for (let bx = xa; bx <= xb; bx += 3) {
			const v = shape(bx, by);
			if (v > best) {
				best = v;
				bx0 = bx;
				by0 = by;
			}
		}
		if (best <= 0) continue;
		for (let by = Math.max(ya, by0 - 3); by <= Math.min(yb, by0 + 3); by++) for (let bx = Math.max(xa, bx0 - 3); bx <= Math.min(xb, bx0 + 3); bx++) {
			const v = shape(bx, by);
			if (v > best) {
				best = v;
				bx0 = bx;
				by0 = by;
			}
		}
		hits.push([
			bx0,
			by0,
			best
		]);
	}
	hits.sort((p, q) => q[2] - p[2]);
	if (hits.length && hits[0][2] >= .6) {
		const pool = hits.filter(([, , s]) => s >= hits[0][2] - .08).slice(0, 5);
		let pick = pool[0];
		if (pool.length > 1) {
			let best = -2;
			for (const h of pool) {
				const v = nccOf(h[0], h[1]);
				if (v > best) {
					best = v;
					pick = h;
				}
			}
			note = `同形候选 ${pool.length} 个，按内容相关裁决 x=${pick[0]} ncc=${best.toFixed(3)}`;
		}
		const [gx, gy, iou] = pick;
		return {
			drag: gx * (a.bgW / BW) - a.pieceOffX,
			score: iou,
			gapLeft: gx * (a.bgW / BW),
			gapTop: gy,
			bgNatW: BW,
			pcNat: PW,
			note,
			top: hits.slice(0, 5)
		};
	}
	const yTip = Number.isFinite(a.tipY) ? a.tipY / 100 * (BW / 2.76) : NaN;
	const yPiece = a.bgW > 0 ? a.pieceOffY * BW / a.bgW : NaN;
	const clampY = (v) => Math.max(0, Math.min(BH - PH, Math.round(v)));
	const window = (anchor, span) => {
		const out = [];
		const y0 = clampY(anchor);
		for (let d = -span; d <= span; d++) {
			const y = y0 + d;
			if (y >= 0 && y + PH <= BH) out.push(y);
		}
		return out;
	};
	let ys = Number.isFinite(yPiece) ? window(yPiece, 24) : [];
	if (!ys.length && Number.isFinite(yTip)) ys = window(yTip, Math.round(PH));
	if (!ys.length) for (let y = 0; y + PH <= BH; y += 2) ys.push(y);
	const anchorY = Number.isFinite(yPiece) ? yPiece : yTip;
	const coarse = makeScorer(3);
	let bestX = 0;
	let bestY = ys[0] ?? 0;
	let bestScore = -2;
	const cands = [];
	for (const y of ys) for (let x = 0; x + PW <= BW; x++) {
		const s = coarse(x, y);
		cands.push([
			x,
			y,
			s
		]);
		if (s > bestScore) {
			bestScore = s;
			bestX = x;
			bestY = y;
		}
	}
	cands.sort((p, q) => q[2] - p[2]);
	const top = [];
	for (const c of cands) {
		if (top.every(([x, y]) => Math.abs(x - c[0]) > PW * .6 || Math.abs(y - c[1]) > PH * .6)) top.push(c);
		if (top.length >= 5) break;
	}
	const near = top.filter(([, , s]) => s >= bestScore - .05);
	if (near.length > 1) {
		let pick = near[0];
		let best = -2;
		for (const c of near) {
			const v = nccOf(c[0], c[1]);
			if (v > best) {
				best = v;
				pick = c;
			}
		}
		note = `并列候选 ${near.length} 个，按内容相关裁决 x=${pick[0]} ncc=${best.toFixed(3)}`;
		bestX = pick[0];
		bestY = pick[1];
		bestScore = pick[2];
	} else if (Number.isFinite(anchorY)) {
		const same = top.filter(([, , s]) => s >= bestScore - .02);
		let pick = null;
		for (const c of same) if (!pick || Math.abs(c[1] - anchorY) < Math.abs(pick[1] - anchorY)) pick = c;
		if (pick) {
			bestX = pick[0];
			bestY = pick[1];
			bestScore = pick[2];
		}
	}
	const fine = makeScorer(1);
	const x0 = Math.max(0, bestX - 8);
	const x1 = Math.min(BW - PW, bestX + 8);
	const y0 = Math.max(0, bestY - 10);
	const y1 = Math.min(BH - PH, bestY + 10);
	let fx = bestX;
	let fy = bestY;
	let fs = -2;
	for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) {
		const s = fine(x, y);
		if (s > fs) {
			fs = s;
			fx = x;
			fy = y;
		}
	}
	bestX = fx;
	bestY = fy;
	bestScore = fs;
	const gapLeft = bestX * (a.bgW / BW);
	return {
		drag: gapLeft - a.pieceOffX,
		score: bestScore,
		gapLeft,
		gapTop: bestY,
		bgNatW: BW,
		pcNat: PW,
		note,
		top
	};
}
/** 下载题目图 + 求缺口；图片是 CDN 直链，必须走 context.request 才能复用页面 UA */
async function match(page, ctx, q, g) {
	if (!q.url1 || !q.url2) return {
		drag: 0,
		score: -1,
		error: "题目图片地址缺失"
	};
	try {
		const [a, b] = await Promise.all([ctx.request.get(q.url1, { timeout: 2e4 }), ctx.request.get(q.url2, { timeout: 2e4 })]);
		const bgB64 = (await a.body()).toString("base64");
		const pcB64 = (await b.body()).toString("base64");
		if (process.env.DY_DUMP_GAP) {
			const dir = process.env.DY_DUMP_GAP === "1" ? join(tmpdir(), "dy-gap") : process.env.DY_DUMP_GAP;
			mkdirSync(dir, { recursive: true });
			const no = ++dumpN;
			writeFileSync(join(dir, `bg-${no}.png`), Buffer.from(bgB64, "base64"));
			writeFileSync(join(dir, `pc-${no}.png`), Buffer.from(pcB64, "base64"));
		}
		const gap = await page.evaluate(matchFn, {
			bgB64,
			pcB64,
			tipY: Number(q.tip_y ?? NaN),
			bgW: g.bgW,
			pieceOffX: g.pieceOffX,
			pieceOffY: g.pieceOffY
		});
		if (gap.dark != null) {
			const natX = (gap.gapLeft ?? 0) * ((gap.bgNatW ?? 0) / Math.max(1, g.bgW));
			log$2.info(`暗剪影命中 原图x=${natX.toFixed(0)} y=${gap.gapTop ?? -1} 暗度=${gap.dark.toFixed(1)} 次优=${(gap.second ?? 0).toFixed(1)}`);
		} else if (gap.note) log$2.info(gap.note);
		return gap;
	} catch (e) {
		return {
			drag: 0,
			score: -1,
			error: `下载题目图片失败: ${String(e).slice(0, 140)}`
		};
	}
}
async function drag(cdp, g, dx, state) {
	await sleep$2(300 + Math.random() * 400);
	const at = (x, y) => [{
		x,
		y,
		id: 1,
		radiusX: 8,
		radiusY: 8,
		force: 1
	}];
	await cdp.send("Input.dispatchTouchEvent", {
		type: "touchStart",
		touchPoints: at(g.btnX, g.btnY)
	});
	await sleep$2(140 + Math.random() * 220);
	let cx = g.btnX;
	const track = humanTrack(dx);
	for (let i = 0; i < track.length; i++) {
		cx += track[i];
		await cdp.send("Input.dispatchTouchEvent", {
			type: "touchMove",
			touchPoints: at(cx, g.btnY + (Math.random() * 2 - 1))
		});
		if (i === Math.floor(track.length * .55)) await sleep$2(40 + Math.random() * 60);
		await sleep$2(10 + Math.random() * 12);
	}
	await sleep$2(160 + Math.random() * 220);
	state.verify = "";
	await cdp.send("Input.dispatchTouchEvent", {
		type: "touchEnd",
		touchPoints: []
	});
}
async function attempt(ctx, cdp, page, input, state) {
	await page.bringToFront().catch(() => void 0);
	if (!await waitFor(async () => await page.locator(".captcha-slider-btn").count() > 0, 3e4)) {
		log$2.warn("等不到滑块按钮");
		return "fail";
	}
	if (!await waitFor(() => !!state.get?.data?.question?.url1, 2e4)) {
		log$2.warn(`没拿到题目图片: ${state.get ? JSON.stringify(state.get).slice(0, 200) : "(无 get 响应)"}`);
		return state.get ? "cool" : "fail";
	}
	const q = state.get?.data?.question;
	if (!q) return "fail";
	await sleep$2(2e3 + Math.random() * 1200);
	if (input.done()) return "ok";
	const cur = await waitFor(async () => {
		const next = await geo(page);
		return next && next.bgW > 0 && next.bgH > 0 && next.pcW > 0 && next.pcH > 0 ? next : null;
	}, 15e3, 300);
	if (!cur) {
		log$2.warn("滑块 DOM 未渲染完");
		return "fail";
	}
	log$2.info(`DOM bg=${cur.bgW}x${cur.bgH} piece=${cur.pcW}x${cur.pcH} off=(${cur.pieceOffX.toFixed(0)},${cur.pieceOffY.toFixed(0)}) 按钮=(${cur.btnX.toFixed(0)},${cur.btnY.toFixed(0)})`);
	const m = await match(page, ctx, q, cur);
	if (m.error || !Number.isFinite(m.drag)) {
		log$2.warn(`缺口匹配失败: ${m.error ?? "unknown"}`);
		return "fail";
	}
	const live = await geo(page) ?? cur;
	const maxDrag = live.bgW - live.pcW - live.pieceOffX;
	const dx = Math.max(4, Math.min(Math.max(4, maxDrag), (m.gapLeft ?? 0) - live.pieceOffX));
	const natX = (m.gapLeft ?? 0) * ((m.bgNatW ?? 0) / Math.max(1, live.bgW));
	log$2.info(`缺口 显示x=${(m.gapLeft ?? 0).toFixed(1)} 原图x=${natX.toFixed(0)} 原图y=${m.gapTop ?? -1} tip_y=${String(q.tip_y ?? "-")} 图=${m.bgNatW ?? 0}x bgW=${live.bgW} 拼图=${m.pcNat ?? 0} 相似度=${m.score.toFixed(3)} 偏移=${live.pieceOffX.toFixed(0)} 上限=${maxDrag.toFixed(0)} → 拖动 ${dx.toFixed(1)}px`);
	if (m.top?.length) log$2.info(`候选 ${m.top.map(([x, y, s]) => `${x},${y}:${s.toFixed(2)}`).join(" | ")}`);
	if (process.env.DY_SLIDE_DRY === "1") {
		log$2.info("DY_SLIDE_DRY=1，跳过拖动");
		return "fail";
	}
	await drag(cdp, live, dx, state);
	const got = await waitFor(() => input.done() || !!state.verify, 2e4);
	if (input.done()) return "ok";
	if (!got) {
		log$2.warn("拖动后 20 秒没等到 verify 响应");
		return "fail";
	}
	let code = 0;
	try {
		code = Number(JSON.parse(state.verify).code ?? 0);
	} catch {}
	if (code === 200) {
		log$2.info("verify 返回 200，验证通过");
		return "ok";
	}
	if (state.verify.includes("5014")) return "cool";
	log$2.warn(`verify 未通过 code=${code}`);
	return "fail";
}
/**
* 起有头浏览器把本机验证页跑成真机形态。
* 真机 HAR 实测：同一 detail 下 verify 500 后可以重新 get 新题再验，直到通过；
* 因此这里在同一决策内重开验证页换题重试（每次都是新的 captchaBody，不是重放旧验证）。
* 5014 是设备/网络的环境判定，换题也没用，立即交回上层。
* 返回 null 表示本模块没跑（禁用/缺依赖/无浏览器），交给手机扫码手动拖。
*/
async function solve(input) {
	if (process.env.DY_SLIDE_AUTO === "0") {
		log$2.info("已禁用自动过滑块（DY_SLIDE_AUTO=0）");
		return null;
	}
	let pw;
	try {
		pw = await import("playwright-core");
	} catch (e) {
		log$2.warn(`未安装 playwright-core，回落扫码模式: ${String(e).slice(0, 120)}`);
		return null;
	}
	const browser = await launch(pw, input.dev);
	if (!browser) {
		log$2.warn("没有可用浏览器（Edge/Chrome），回落扫码模式");
		return null;
	}
	const vp = viewport(input.dev);
	const ctx = await browser.newContext({
		userAgent: webViewUa(input.dev),
		viewport: {
			width: vp.width,
			height: vp.height
		},
		screen: {
			width: vp.width,
			height: vp.height
		},
		deviceScaleFactor: vp.dpr,
		isMobile: true,
		hasTouch: true,
		locale: "zh-CN",
		timezoneId: "Asia/Shanghai"
	});
	log$2.info(`视口 ${vp.width}x${vp.height}@${vp.dpr}x = 物理 ${Math.round(vp.width * vp.dpr)}x${Math.round(vp.height * vp.dpr)}（声明 ${input.dev.resolution}）`);
	const page = await ctx.newPage();
	const cdp = await ctx.newCDPSession(page);
	await cdp.send("Emulation.setUserAgentOverride", {
		userAgent: webViewUa(input.dev),
		acceptLanguage: "zh-CN",
		platform: "Linux armv8l",
		userAgentMetadata: {
			brands: [
				{
					brand: "Chromium",
					version: "120"
				},
				{
					brand: "Google Chrome",
					version: "120"
				},
				{
					brand: "Not-A.Brand",
					version: "99"
				}
			],
			fullVersionList: [
				{
					brand: "Chromium",
					version: "120.0.6099.144"
				},
				{
					brand: "Google Chrome",
					version: "120.0.6099.144"
				},
				{
					brand: "Not-A.Brand",
					version: "99.0.0.0"
				}
			],
			fullVersion: "120.0.6099.144",
			platform: "Android",
			platformVersion: input.dev.osVersion ?? "17.0.0",
			architecture: "arm",
			model: input.dev.deviceType ?? "PLC110",
			mobile: true,
			bitness: "",
			wow64: false
		}
	});
	await page.addInitScript({ content: "globalThis.__name = globalThis.__name || ((f) => f);" });
	await cdp.send("Emulation.setTouchEmulationEnabled", {
		enabled: true,
		maxTouchPoints: 5
	});
	if (process.env.DY_PAYLOAD === "1") await page.addInitScript({ content: PAYLOAD_HOOK });
	const state = {
		get: null,
		verify: ""
	};
	page.on("response", (resp) => {
		const u = resp.url();
		if (u.includes("/captcha/get")) resp.json().then((v) => {
			state.get = v;
		}).catch(() => void 0);
		else if (u.includes("/captcha/verify")) resp.text().then((t) => {
			state.verify = t;
		}).catch(() => void 0);
	});
	try {
		const ROUNDS = 3;
		let step = "fail";
		for (let round = 1; round <= ROUNDS; round++) {
			state.get = null;
			state.verify = "";
			log$2.info(`打开验证页（第 ${round} 题）`);
			await page.goto(input.url, {
				waitUntil: "domcontentloaded",
				timeout: 3e4
			}).catch((e) => {
				log$2.warn(`打开验证页失败: ${String(e).slice(0, 120)}`);
			});
			if (input.done()) return null;
			if (round === 1) {
				const env = await page.evaluate(() => {
					const g = globalThis;
					return `${g.navigator.platform} touch=${g.navigator.maxTouchPoints} cores=${g.navigator.hardwareConcurrency} dpr=${g.devicePixelRatio}`;
				}).catch(() => "-");
				log$2.info(`页面环境 ${env}`);
			}
			step = await attempt(ctx, cdp, page, input, state);
			if (process.env.DY_PAYLOAD === "1") await dumpPayload(page);
			if (step === "ok" || step === "cool" || input.done()) break;
			if (round < ROUNDS) log$2.info(`第 ${round} 题未通过，同一决策重新取题`);
		}
		if (step !== "ok") log$2.warn(`本次自动过滑块未通过（${step}），交回上层`);
		return step;
	} finally {
		await ctx.close().catch(() => void 0);
		await browser.close().catch(() => void 0);
		log$2.info("自动过滑块已退出");
	}
}
//#endregion
//#region src/app/slide.ts
/** 1105 滑块本地验证页：官方 bdturing SDK 在本次决策上完成验证，通过后上层自动回填票据重发 */
const log$1 = createLog({ tag: "slide" });
/** 只放行抖音自家的验证域，避免本地服务被当成任意代理 */
const PROXY_ALLOW = /(^|\.)(zijieapi\.com|bytedance\.com|snssdk\.com|amemv\.com)$/i;
/** 真机 /captcha/* 的接入点由决策的 server_sdk_env.idc 决定（HAR 实测 verify-lf）；写死会与设备区域不符 */
function appHost(challenge) {
	const env = challenge.decision.server_sdk_env;
	const raw = typeof env === "string" ? env : JSON.stringify(env ?? {});
	try {
		const idc = JSON.parse(raw).idc;
		if (idc) return `https://verify-${idc}.zijieapi.com`;
	} catch {}
	return "https://verify-lf.zijieapi.com";
}
const PAGE_HOST = "https://verify.zijieapi.com";
/** HAR 里 /captcha/* 只带这一个 cookie；串入 passport 会话会暴露「同一 did 既像浏览器又持有 App 会话」 */
const CAPTCHA_COOKIE = "ticket_guard_has_set_public_key=1";
/** 内置 SDK 副本；缺失时留空，让上层跳过滑块 */
const SDK_DIR = findAsset("captcha.1.0.0.1007.js");
const SDK_FILE = SDK_DIR ? join(SDK_DIR, "captcha.1.0.0.1007.js") : "";
/** verify_center 是验证中心下发给网页/H5 的决策：改写成 App 通道后「声明」与验证体来源矛盾，实测 5014 */
function h5() {
	return process.env.DY_H5 === "1";
}
/** 真机滑块通道固定上报整屏 1272*2800；passport 其他接口声明的是可用区 1272*2603，两者不能混用 */
function captchaResolution() {
	return process.env.DY_CAPTCHA_RESOLUTION ?? "1272*2800";
}
/** 真机 /captcha/get|verify 的 App 通道参数（HAR 抄录）；浏览器形态的 UA + web 参数会被判 5014 */
function appQuery(dev, ids, subtype) {
	const did = ids.device_id;
	const base = [
		["aid", dev.aid],
		["lang", "zh"],
		["bd_version", "1.0.0.1007"],
		["subtype", subtype],
		["mode", subtype],
		["did", did],
		["device_id", did],
		["os_name", dev.os],
		["platform", "app"],
		["os_type", 0],
		["h5_sdk_version", "3.5.81"],
		["webdriver", "false"],
		["tmp", Date.now()],
		["verify_host", "https://verify.zijieapi.com/"],
		["app_name", dev.appName],
		["locale", "zh_CN"],
		["ch", dev.channel],
		["channel", dev.channel],
		["iid", ids.iid],
		["vc", dev.versionName],
		["app_verison", dev.versionName],
		["region", "cn"],
		["use_native_report", 1],
		["use_jsb_request", 1],
		["verify_cancellable", 0],
		["orientation", 0],
		["resolution", captchaResolution()],
		["sdk_version", "4.2.1.cn"],
		["os_version", dev.osVersion],
		["device_brand", dev.deviceBrand],
		["device_model", dev.deviceType],
		["version_code", dev.manifestVersionCode],
		["version_name", dev.versionName],
		["device_type", dev.deviceType],
		["device_platform", dev.devicePlatform],
		["use_dialog_size_v2", 1]
	];
	const q = new URLSearchParams();
	for (const [k, v] of base) q.set(k, String(v));
	return q;
}
/**
* 把页面 SDK 发往 verify.zijieapi.com 的 /captcha/* 改写成真机 App 请求。
* 必须保留 SDK 自己的 query：页面 SDK 会把 challenge 绑定的加密字段塞在 URL 里，
* 整包重建只剩抄来的常量，服务端就认不出这是它自己下发的环境。
* a_bogus / msToken 由页面 SDK 按当前环境现算，删掉等于让一条自报 app 的请求缺环境凭据：
* 实测删掉恒 5014，保留才有 200。
*/
function rewrite(target, dev, ids, challenge) {
	const u = new URL(target);
	const q = new URLSearchParams(u.searchParams);
	for (const [k, v] of appQuery(dev, ids, challenge.subtype || "slide")) q.set(k, v);
	q.set("tmp", String(Date.now()));
	if (/\/captcha\/verify$/i.test(u.pathname)) {
		const d = { ...challenge.decision };
		if (!d["verify_ticket"] && challenge.verifyTicket) d["verify_ticket"] = challenge.verifyTicket;
		q.delete("verify_data");
		q.append("verify_data", JSON.stringify(d));
	}
	return `${appHost(challenge)}${u.pathname}?${q.toString()}`;
}
const esc = (v) => JSON.stringify(v).replace(/</g, "\\u003c");
/**
* 自建验证页：不代理官方 rmc 页，因为官方页会把浏览器指纹塞进 env 上报，
* 与 App 通道声明的设备互相矛盾，bdturing 直接回 5014。
* 轨迹与加密体由官方 SDK 自己算。env 也必须是 SDK 原样采集：SDK 会检测 navigator/WebGL
* 上的 JS 覆盖（defineProperty），命中后会把 GPU/触摸数据抹掉，服务端判环境不可信 → 5014。
* 所以这里不做任何指纹改写，移动形态只通过 Playwright 的 UA/视口/触摸真实模拟。
*/
function page$1(decision, dev, ids) {
	const info = {
		aid: dev.aid,
		appName: dev.appName,
		lang: "zh",
		did: h5() ? "" : ids.device_id,
		iid: h5() ? ids.iid : "",
		fp: "",
		repoId: "",
		pageId: ""
	};
	return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>安全验证</title>
<style>
 html,body{margin:0;height:100%;background:#f6f7f9;font:14px/1.5 -apple-system,"Segoe UI",Arial,sans-serif}
 #wrap{max-width:420px;margin:24px auto;background:#fff;border-radius:10px;padding:16px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
 #hint{color:#666;margin:0 0 12px}
 #out{white-space:pre-wrap;word-break:break-all;color:#666;margin-top:12px;font-size:12px}
</style></head>
<body>
<div id="wrap">
  <p id="hint">加载中…</p>
  <div id="captcha_container"></div>
  <div id="out"></div>
</div>
<script>
window.gfdatav1 = {env:'prod', ver:'1.0.0.1007'};
window.bdCaptcha_slardar = function(){};
window.collectEvent = function(){};
<\/script>
<script src="/captcha-sdk.js" crossorigin="anonymous"><\/script>
<script>
(function(){
  var Q = ${esc(info)}, VD = ${esc(JSON.stringify(decision))};
  var hint = document.getElementById('hint');
  try {
    var N = {aid: Q.aid, appName: Q.appName, lang: Q.lang,
             fp: Q.fp || '', repoId: Q.repoId || '', pageId: Q.pageId || ''};
    if (Q.did) N.did = Q.did;
    if (Q.iid) N.iid = Q.iid;
    var c = new window.bdCaptcha.CaptchaVerify({
      info: N,
      ele: 'captcha_container',
      host: location.origin,
      viewport: false,
      hideCloseBtn: true,
      theme: {},
      env: {},
      successCb: function(){ hint.textContent = '验证通过，请回到电脑继续'; },
      closeCb: function(){},
      feedbackSubmitCb: function(){},
      log: function(){}
    });
    c.init();
    c.render(VD);
    // 环境指纹是异步采集的，加载后立刻拖会采不全 → 服务端判环境不可信
    hint.textContent = '等“拼图”出现 2~3 秒再拖';
  } catch (e) {
    hint.textContent = '验证组件加载失败：' + e;
  }
})();
<\/script>
</body></html>`;
}
function readBody(req) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		req.on("data", (c) => chunks.push(c));
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}
function lanIp() {
	for (const list of Object.values(os$1.networkInterfaces())) for (const item of list ?? []) if (item.family === "IPv4" && !item.internal) return item.address;
	return "127.0.0.1";
}
/**
* /captcha/* 的请求头。
* 默认只发 bdturing 自身需要的头（真机 HAR 里 /captcha/* 也只带那一个公钥 cookie）。
* DY_CAPTCHA=full 时改用 passport 会话票据头做单变量排查：api.ts 的注释断言缺票据会被判 5014，
* 而 unidbg 抓包显示真机 /captcha/* 确实不带会话票据；两说矛盾，用实测裁决。
* DY_CAPTCHA=plain 时连 App 签名头也不加：验证体是网页 SDK 采的，App 网关签名与它是否自洽需单变量实测。
*/
/** 排查用：把真机抓到的 x-bdms-payload 塞进 verify 体，验证服务端是否强制要求这个原生环境上报字段 */
function withBdms(body) {
	const file = process.env.DY_BDMS;
	if (!file) return body;
	try {
		const j = JSON.parse(body.toString("utf8"));
		j["x-bdms-payload"] = readFileSync(file, "utf8").trim();
		return Buffer.from(JSON.stringify(j));
	} catch {
		return body;
	}
}
async function sendCaptcha(target, method, body, type, dev, ids, auth, sign) {
	const u = new URL(target);
	if (!PROXY_ALLOW.test(u.hostname)) throw new Error(`拒绝代理: ${u.hostname}`);
	const cm = process.env.DY_CAPTCHA;
	const full = cm === "full";
	const plain = cm === "plain";
	const headers = full ? headOf(auth, dev, ids, "n=1;t=0;s=-1;p=0", true) : [
		["user-agent", ua(dev)],
		["x-ss-dp", String(dev.aid)],
		["cookie", CAPTCHA_COOKIE]
	];
	headers.push(["x-vc-bdturing-sdk-version", "4.2.1.cn"]);
	headers.push(["content-type", type ?? "application/json; charset=utf-8"]);
	if (sign && !plain) {
		if (ids.client_key && !full) headers.push(["x-bd-client-key", ids.client_key]);
		try {
			const sig = soSign(target, body.length ? body : void 0, {
				deviceId: ids.device_id,
				installId: ids.iid
			});
			for (const [k, v] of Object.entries(sig)) headers.push([k, v]);
		} catch (e) {
			log$1.warn(`verify 签名失败，服务端会按风控处理：${String(e).slice(0, 200)}`);
		}
	}
	return request({
		url: target,
		method,
		headers,
		body: body.length ? body : void 0
	});
}
/** H5 通道：决策 from=verify_center 时验证体本就是网页 SDK 采的，原样透传浏览器请求才自洽 */
async function sendH5(target, method, body, type, uaText) {
	const u = new URL(target);
	if (!PROXY_ALLOW.test(u.hostname)) throw new Error(`拒绝代理: ${u.hostname}`);
	return request({
		url: target,
		method,
		headers: [
			["user-agent", uaText],
			["accept", "*/*"],
			["accept-language", "zh-CN,zh;q=0.9"],
			["x-vc-bdturing-sdk-version", "4.2.1.cn"],
			["cookie", CAPTCHA_COOKIE],
			["content-type", type ?? "application/json; charset=utf-8"]
		],
		body: body.length ? body : void 0
	});
}
/** i18n 等非 get/verify 请求原样转发：它们由页面侧发起，补上真机静态头与会话票据才像 App 调用 */
async function sendRaw(target, method, body, type, dev, auth) {
	const u = new URL(target);
	if (!PROXY_ALLOW.test(u.hostname)) throw new Error(`拒绝代理: ${u.hostname}`);
	const headers = [
		["host", u.hostname],
		["user-agent", ua(dev)],
		["x-ss-dp", String(dev.aid)],
		["x-vc-bdturing-sdk-version", "4.2.1.cn"],
		["x-tt-request-tag", "n=1;t=0;s=-1;p=0"],
		["x-bd-kmsv", "1"],
		["sdk-version", "2"],
		["accept-encoding", "gzip, deflate, br"]
	];
	const cookie = auth.cookie();
	if (cookie) headers.push(["cookie", cookie]);
	const token = auth.tokens["x-tt-token"];
	if (token) headers.push(["x-tt-token", token]);
	if (auth.mfaToken) headers.push(["x-tt-passport-mfa-token", auth.mfaToken]);
	const csrf = auth.csrf();
	if (csrf) headers.push(["x-tt-passport-csrf-token", csrf]);
	headers.push(["x-tt-passport-verify-portrait", auth.portrait]);
	if (body.length) headers.push(["content-type", type ?? "application/json; charset=utf-8"]);
	return request({
		url: target,
		method,
		headers,
		body: body.length ? body : void 0
	});
}
async function terminalQr(url) {
	try {
		const qr = await import("qrcode");
		log$1.info(`\n${await qr.toString(url, {
			type: "terminal",
			small: true
		})}`);
	} catch {}
}
/** 起本地验证服务；返回的 Slide 在 verify 返回 200 时 wait() 立即完成 */
async function serve(opts) {
	const { challenge, dev, ids, auth } = opts;
	const port = opts.port ?? 8787;
	const hits = [];
	let settle;
	let settled = false;
	let result = "timeout";
	const verified = new Promise((resolve) => {
		settle = resolve;
	});
	const timer = setTimeout(() => {
		log$1.warn(`等待滑块超时（${Math.round((opts.timeoutMs ?? 3e5) / 1e3)}s）`);
		finish("timeout");
	}, opts.timeoutMs ?? 3e5);
	/** 只认第一次结果：verify 200、自动失败、超时、关闭可能并发触发 */
	const finish = (r) => {
		if (settled) return;
		settled = true;
		result = r;
		clearTimeout(timer);
		settle(r === "ok");
	};
	const handle = async (raw, method, body, type, res, meta) => {
		hits.push(`${method} ${raw.slice(0, 200)}`);
		const path = new URL(raw).pathname;
		const isCaptcha = /\/captcha\/(get|verify)$/i.test(path);
		const isVerify = /\/captcha\/verify$/i.test(path);
		const h5Mode = h5();
		const cm = process.env.DY_CAPTCHA;
		const mode = cm === "host" || cm === "raw" ? cm : "app";
		const target = isCaptcha && !h5Mode ? mode === "raw" ? raw : mode === "host" ? `${appHost(challenge)}${raw.replace(/^https?:\/\/[^/]+/i, "")}` : rewrite(raw, dev, ids, challenge) : raw;
		log$1.info(`${method} ${path} ip=${meta.ip} 通道=${h5Mode && isCaptcha ? "h5" : mode} 头=${isCaptcha && !h5Mode ? cm === "full" ? "full" : cm === "plain" ? "plain" : "base" : "-"} ua=${meta.ua.slice(0, 120)}${body.length ? ` body=${body.length}B` : ""}`);
		try {
			const out = isCaptcha ? h5Mode ? await sendH5(target, method, body, type, meta.ua) : await sendCaptcha(target, method, isVerify ? withBdms(body) : body, type, dev, ids, auth, isVerify) : await sendRaw(target, method, body, type, dev, auth);
			res.writeHead(200, {
				"content-type": out.headers["content-type"] ?? "application/json; charset=utf-8",
				"cache-control": "no-store",
				"access-control-allow-origin": "*"
			});
			res.end(out.body);
			log$1.info(`${method} ${path} → ${out.status} logid=${out.headers["x-tt-logid"] ?? "-"} ${out.text.slice(0, 300)}`);
			if (!isVerify) return;
			const code = Number(out.json?.code ?? -1);
			if (code === 200) {
				finish("ok");
				return;
			}
			if (out.text.includes("5014")) {
				log$1.warn("verify 5014（环境判定），需换网络后重试");
				finish("cool");
				return;
			}
			log$1.warn(`verify 未通过 code=${code}`);
		} catch (e) {
			log$1.warn(`${method} ${path} 失败：${String(e)}`);
			res.writeHead(502, { "content-type": "application/json" });
			res.end(JSON.stringify({
				code: 502,
				message: String(e)
			}));
		}
	};
	const route = async (req, res) => {
		const u = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
		const method = (req.method ?? "GET").toUpperCase() === "POST" ? "POST" : "GET";
		const ip = String(req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? "-");
		const uaText = String(req.headers["user-agent"] ?? "-");
		if (method === "GET" && (u.pathname === "/" || u.pathname === "/slide")) {
			log$1.info(`打开验证页 ip=${ip} ua=${uaText.slice(0, 160)}`);
			res.writeHead(200, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store"
			});
			res.end(page$1(challenge.decision, dev, ids));
			return;
		}
		if (method === "GET" && u.pathname === "/captcha-sdk.js" && SDK_FILE) {
			const body = readFileSync(SDK_FILE);
			res.writeHead(200, {
				"content-type": "application/javascript; charset=utf-8",
				"content-length": String(body.length),
				"cache-control": "no-store"
			});
			res.end(body);
			return;
		}
		if (u.pathname.startsWith("/captcha/")) {
			const body = await readBody(req);
			if (process.env.DY_DUMP_GAP && method === "POST") {
				const dir = process.env.DY_DUMP_GAP === "1" ? join(os$1.tmpdir(), "dy-gap") : process.env.DY_DUMP_GAP;
				mkdirSync(dir, { recursive: true });
				writeFileSync(join(dir, "verify-body.txt"), `${decodeURIComponent(req.url ?? "")}\n\n${body.toString("utf8")}`);
			}
			await handle(`${PAGE_HOST}${req.url ?? ""}`, method, body, req.headers["content-type"], res, {
				ip,
				ua: uaText
			});
			return;
		}
		if (/^\/(monitor_web|monitor_browser)\//.test(u.pathname)) {
			res.writeHead(204);
			res.end();
			return;
		}
		res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
		res.end("not found");
	};
	const server = http.createServer((req, res) => {
		route(req, res).catch((e) => {
			res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
			res.end(`server error: ${String(e)}`);
		});
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(port, "0.0.0.0", () => resolve());
	});
	const url = `http://${lanIp()}:${port}/slide`;
	log$1.info(`本地验证页已启动：${url}`);
	log$1.info(`手机需与电脑同网；打不开请放行 Node 入站端口 ${port}`);
	log$1.info(`票据 ${challenge.verifyTicket || "(无)"} 决策来源 ${String(challenge.decision["from"] ?? "-")}，拖动通过后自动继续登录`);
	await opts.onUrl?.(url);
	terminalQr(url);
	log$1.info("已开始自动过滑块（本机 Edge/Chrome），失败仍可手机扫码手动拖");
	solve({
		url: `http://127.0.0.1:${port}/slide`,
		dev,
		done: () => settled
	}).then((step) => {
		if (step) finish(step);
	}).catch((e) => log$1.warn(`自动过滑块异常: ${String(e).slice(0, 160)}`));
	return {
		url,
		port,
		hits,
		wait: () => verified.finally(() => {
			settled = true;
			clearTimeout(timer);
			server.close();
		}),
		result: () => result,
		close: () => {
			finish("closed");
			server.close();
		}
	};
}
//#endregion
//#region src/app/pb.ts
/** App 侧 IM protobuf 信封：按真机 Android 字段组装，schema 复用 web */
let seq = 0;
/** 明文 unread_count 抓包还原的 envelope 默认值；缺省字段会被网关判非法 */
function pack(dev, ids, call) {
	const env = loadRoot().lookupType("im.RequestEnvelope");
	const g = zt(ids);
	const ts = Math.floor(Date.now() / 1e3);
	const message = env.create({
		cmd: call.cmd,
		sequenceId: ++seq,
		sdkVersion: "5.0.3.0-rc.11-SNAPSHOT",
		token: call.token ?? "",
		refer: 1,
		inboxType: 0,
		buildNumber: "5030",
		body: { [call.field]: call.body ?? {} },
		deviceId: ids.device_id,
		channel: dev.channel,
		devicePlatform: dev.devicePlatform,
		deviceType: dev.deviceType,
		osVersion: dev.osVersion,
		versionCode: String(dev.versionCode),
		headers: {
			app_name: dev.appName,
			iid: ids.iid,
			version_code: String(dev.versionCode),
			net_mcc_mnc: dev.mccMnc,
			aid: String(dev.aid),
			sim_mcc_mnc: dev.mccMnc,
			"flow-tag": "new",
			"user-agent": "okhttp/3.12.13.2"
		},
		configId: 0,
		authType: 4,
		clientCert: g.cert,
		clientData: clientData(ids, call.path, "", ts),
		reePublicKey: g.reeKey,
		iterVersion: "2",
		biz: "douyin",
		access: "douyin_main"
	});
	return Buffer.from(env.encode(message).finish());
}
/** 解密后的响应信封转普通对象，int64 统一转字符串避免精度丢失 */
function unpack(res) {
	if (!res.ready) throw new Error(`pb 响应未解密 status=${res.status}`);
	const env = loadRoot().lookupType("im.ResponseEnvelope");
	return env.toObject(env.decode(res.raw), {
		longs: String,
		defaults: true
	});
}
/** 组装并下发一次 pb 查询，返回 ResponsePayload 对应 body */
async function pbQuery(im, dev, ids, path, cmd, field, body, ok = []) {
	const env = unpack(await im.call({
		path,
		enc: "pb",
		body: pack(dev, ids, {
			cmd,
			field,
			body,
			token: await im.token(),
			path
		})
	}));
	const status = Number(env.statusCode ?? 0);
	if (status !== 0 && !ok.includes(status)) throw new Error(`${path} 失败 statusCode=${String(env.statusCode)} ${String(env.errorDesc ?? "")}`);
	return env.body ?? {};
}
//#endregion
//#region src/app/wire.ts
/** App 发送内容构造：统一消息体转成 IM 帧的 messageType 与 content；媒体只接受已上传资产 */
/**
* 把统一消息体转成 IM 帧字段。
* App 网关不代传媒体，输入源（URL/本地/字节）需先在 cookie 通道上传，这里拒绝以免发出坏帧；
* 表情仅支持完整资源直链，小表情 id 与 im-resource id 的解析依赖 web 接口，App 通道不可用。
*/
function wire(body, uid, conId) {
	switch (body.type) {
		case "text": {
			if (body.atAll) return {
				messageType: 7,
				content: buildAtAllTextContent(body.text),
				atAll: true
			};
			const { content, mentions } = textWithAts(body.text, body.ats, conId);
			return {
				messageType: 7,
				content,
				...mentions.length ? { mentionedUsers: [...new Set(mentions.map((m) => m.uid))] } : {}
			};
		}
		case "image":
			if (isInput(body.image)) return err({ image: body.image });
			return {
				messageType: 27,
				content: buildImageContent(body.image)
			};
		case "video": {
			const video = body.video;
			if ("source" in video) return err({ video });
			if (!("asset" in video)) return {
				messageType: 30,
				content: buildVideoContent(video)
			};
			const { asset, poster, width, height } = video;
			return {
				messageType: 30,
				content: buildVideoContent({
					...asset,
					...poster ? { poster } : {},
					...width !== void 0 ? { width } : {},
					...height !== void 0 ? { height } : {}
				})
			};
		}
		case "file": {
			const file = body.file;
			if ("source" in file) return err({ file });
			return {
				messageType: 150,
				content: buildFileContent("asset" in file ? file.asset : file)
			};
		}
		case "share": return {
			messageType: 8,
			content: buildShareContent(body.share, uid)
		};
		case "userCard": return {
			messageType: 25,
			content: buildUserCardContent(body.user)
		};
		case "emoji":
			if (!/^https?:\/\//.test(body.emoji)) return err({ emoji: body.emoji });
			return {
				messageType: 5,
				content: buildEmojiContent(body.emoji, body.text)
			};
		case "card": return {
			messageType: 110,
			content: buildCardContent(body.card, body.text ?? body.card.title ?? "")
		};
		case "location": return {
			messageType: 502,
			content: buildLocationContent(body.location)
		};
		case "groupCard": return {
			messageType: 58,
			content: buildGroupCardContent(body.groupCard, uid)
		};
		default: return err({ type: body.type });
	}
}
//#endregion
//#region src/app/conv.ts
/** App 会话语义：会话、历史消息、已读游标等 protobuf 查询，经 IM 加密封装下发 */
/** path 以真机抓包为准：get_read_index/get_min_index 在 /v3 下 */
const PATH$1 = {
	list: "/v1/conversation/list",
	infos: "/v2/conversation/get_info_list",
	info: "/v2/conversation/get_info",
	history: "/v1/message/get_by_conversation",
	read: "/v3/conversation/mark_read",
	readIndex: "/v3/conversation/get_read_index",
	minIndex: "/v3/conversation/get_min_index",
	userMsg: "/v3/message/get_user_message",
	send: "/v1/message/send",
	create: "/v2/conversation/create",
	stranger: "/v1/stranger/get_conversation_list",
	audit: "/v1/conversation/get_audit_list",
	participantsRead: "/v1/conversation/batch_get_conversation_participants_readindex",
	recent: "/v3/message/get_recent_stranger_message/",
	participants: "/v1/conversation/participants_list",
	members: "/v1/conversation/get_member_list",
	memberBatch: "/v1/conversation/batch_get_member_list",
	mget: "/v1/conversation/mget_participants",
	marks: "/v1/message/pull_mark",
	cmds: "/v1/conversation/get_recent_cmd_conv",
	range: "/v1/message/get_message_by_index_v2_range/",
	init: "/v1/message/get_message_by_init",
	thread: "/v1/message/get_thread_message_by_init",
	msgById: "/v1/message/get_message_by_server_id",
	msgByIds: "/v1/message/get_messages_by_server_id_list",
	byTime: "/v1/message/get_from_conversation_by_time",
	mark: "/v1/message/mark",
	modifyExt: "/v1/message/modify_ext",
	cmdRange: "/v1/message/get_cmd_message_range",
	specified: "/v3/conversation/specified_message_list",
	favorite: "/v2/conversation/get_by_favorite",
	top: "/v2/conversation/get_by_top",
	batchRead: "/v2/conversation/batch_mark_read",
	batchDelete: "/v1/conversation/batch_delete",
	clearMsg: "/v2/conversation/clear_message",
	recentStrangerConv: "/v1/conversation/get_recent_stranger_conv",
	threadSub: "/v1/conversation/update_thread_subscribe_status"
};
/** protobufjs 的 keepCase=false 只认 camelCase，写 snake_case 会被静默丢弃 */
function ref(id) {
	return {
		conversationId: id.conversationId ?? "",
		conversationShortId: id.shortId,
		conversationType: id.type ?? 0
	};
}
var Conv = class {
	im;
	dev;
	ids;
	constructor(im, dev, ids) {
		this.im = im;
		this.dev = dev;
		this.ids = ids;
	}
	call(path, cmd, field, body, ok) {
		return pbQuery(this.im, this.dev, this.ids, path, cmd, field, body, ok);
	}
	/** 会话列表（cmd=2006） */
	list(opts = {}) {
		return this.call(PATH$1.list, 2006, "conversationList", {
			listType: opts.type ?? 0,
			cursor: opts.cursor ?? 0,
			sortType: opts.sort ?? 0,
			limit: opts.limit ?? 20
		});
	}
	/** 按 id 批量取会话详情（cmd=610） */
	infos(list) {
		return this.call(PATH$1.infos, 610, "getConversationInfoListV2", { conversationInfoList: list.map(ref) });
	}
	/** 单个会话详情（cmd=608） */
	info(id) {
		return this.call(PATH$1.info, 608, "getConversationInfoV2", ref(id));
	}
	/** 历史消息（cmd=301） */
	history(opts) {
		return this.call(PATH$1.history, 301, "conversationMessages", {
			...ref(opts),
			direction: opts.direction ?? 0,
			anchorIndex: opts.anchor ?? 0,
			limit: opts.limit ?? 20
		});
	}
	/** 标记已读（cmd=2002，body oneof 仍占 tag=604） */
	read(opts) {
		return this.call(PATH$1.read, 2002, "markConversationRead", {
			...ref(opts),
			readMessageIndex: opts.readIndex,
			readMessageIndexV2: opts.readIndexV2,
			convUnreadCount: opts.unread,
			totalUnreadCount: opts.totalUnread,
			readBadgeCount: opts.badge,
			ticket: opts.ticket ?? ""
		});
	}
	/** 各成员已读游标（cmd=2000） */
	readIndex(id) {
		return this.call(PATH$1.readIndex, 2e3, "getReadIndex", ref(id));
	}
	/** 最小同步游标（cmd=2001） */
	minIndex(id) {
		return this.call(PATH$1.minIndex, 2001, "getMinIndex", ref(id));
	}
	/** 增量拉会话/消息并下发 cmd 版本游标（cmd=12048） */
	userMessage(opts = {}) {
		return this.call(PATH$1.userMsg, 12048, "getUserMessage", {
			version: opts.version ?? 0,
			cmdIndex: opts.cmdIndex ?? 1,
			strangerVersion: opts.strangerVersion,
			readVersion: opts.readVersion ?? 1,
			source: opts.source ?? "",
			consultVersion: opts.consultVersion ?? 1,
			notifyVersion: opts.notifyVersion,
			threadVersion: opts.threadVersion ?? 1,
			threadReadVersion: opts.threadReadVersion ?? 1,
			needRecentConvReadInfo: opts.needReadInfo,
			cmdMessageChainV2Index: opts.chainIndex ?? 1
		});
	}
	/** 发送消息（cmd=100）：body 传统一消息体，或直接给 messageType + content */
	async send(opts) {
		const refMsg = opts.ref;
		const w = opts.body && wire(opts.body, await this.im.uid(), opts.conversationId);
		const type = w?.messageType ?? opts.messageType ?? 7;
		const content = normalizeDesktopTextMessageContent(w?.content ?? opts.content ?? "", type);
		return this.call(PATH$1.send, 100, "sendMessage", {
			...ref(opts),
			content,
			ext: w?.atAll ? {
				"s:mentioned_users": "0",
				...opts.ext
			} : opts.ext,
			messageType: type,
			clientMessageId: opts.clientMessageId ?? "",
			mentionedUsers: w?.atAll ? ["0"] : w?.mentionedUsers ?? opts.mentionedUsers,
			threadId: opts.threadId,
			refMsgInfo: refMsg && {
				referencedMessageId: refMsg.id,
				hint: refMsg.hint,
				rootMessageId: refMsg.rootId,
				rootMessageConvIndex: refMsg.rootIndex
			}
		});
	}
	/** 创建会话（cmd=609） */
	create(opts) {
		return this.call(PATH$1.create, 609, "createConversationV2", {
			conversationType: opts.type ?? 1,
			participants: opts.users,
			persistent: opts.persistent ?? true,
			idempotentId: opts.idempotentId ?? "",
			name: opts.name,
			avatarUrl: opts.avatar,
			description: opts.desc,
			bizExt: opts.bizExt,
			ext: opts.ext
		});
	}
	/** 陌生人会话列表（外层 cmd=1001，body tag=1000） */
	strangerList(opts = {}) {
		return this.call(PATH$1.stranger, 1001, "strangerConversationList", {
			cursor: opts.cursor ?? 0,
			source: opts.source ?? 0,
			scene: opts.scene ?? 0
		});
	}
	/** 会话审核列表（cmd=2027） */
	auditList(opts = {}) {
		return this.call(PATH$1.audit, 2027, "getConversationAuditList", {
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 20,
			convShortId: opts.shortId,
			noClearUnread: opts.keepUnread ?? false
		});
	}
	/** 批量查各成员已读游标（cmd=2038） */
	participantsReadIndex(id) {
		return this.call(PATH$1.participantsRead, 2038, "getConversationParticipantsReadIndex", {
			conversationId: id.conversationId ?? "",
			conversationShortId: id.shortId,
			getUserReadIndex: 0
		});
	}
	/** 最近陌生人消息（cmd=12047） */
	recentStranger(opts = {}) {
		return this.call(PATH$1.recent, 12047, "getRecentStrangerMessage", {
			latestStrangerVersion: opts.latest,
			earliestStrangerVersion: opts.earliest,
			source: opts.source ?? "",
			newUser: opts.newUser ?? 0,
			bizInfo: opts.bizInfo
		});
	}
	/** 会话参与者分页（cmd=605） */
	participants(opts = {}) {
		return this.call(PATH$1.participants, 605, "conversationParticipants", {
			...ref(opts),
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 50
		});
	}
	/** 会话成员列表（cmd=12060） */
	members(opts = {}) {
		return this.call(PATH$1.members, 12060, "getConversationMemberListBody", {
			...ref(opts),
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 50
		});
	}
	/** 批量取多个会话成员（cmd=12061） */
	membersBatch(list) {
		return this.call(PATH$1.memberBatch, 12061, "batchGetConversationMemberListBody", { batchMemberList: list.map((o) => ({
			...ref(o),
			cursor: o.cursor ?? 0,
			limit: o.limit ?? 50
		})) });
	}
	/** 按 uid 精确取成员（cmd=654） */
	membersByUid(id, users) {
		return this.call(PATH$1.mget, 654, "mgetConversationParticipantsBody", {
			...ref(id),
			participants: users
		});
	}
	/** 按标记位增量拉消息（cmd=2037） */
	marks(opts = {}) {
		return this.call(PATH$1.marks, 2037, "pullMarkMessageBody", {
			...ref(opts),
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 20,
			asc: opts.asc ?? false,
			actionType: opts.actionType ?? 0,
			tag: opts.tag,
			clearUnreadCount: opts.clearUnread ?? false
		});
	}
	/** 最近控制类消息会话（cmd=12062） */
	cmds(opts = {}) {
		return this.call(PATH$1.cmds, 12062, "getRecentCmdConv", {
			cmdMessageConvVersion: opts.version ?? 0,
			reverse: opts.reverse ?? false,
			source: opts.source ?? ""
		});
	}
	/** 会话内控制类消息（cmd=2040） */
	cmdMessages(opts = {}) {
		return this.call("/v1/message/get_cmd_message/", 2040, "getCmdMessageBody", {
			cmdIndex: opts.version ?? 0,
			source: opts.source ?? "",
			newUser: 0
		});
	}
	/** 按会话内 v2 索引区间取消息（cmd=2041） */
	range(opts) {
		return this.call(PATH$1.range, 2041, "getMessageInfoByIndexV2RangeBody", {
			...ref(opts),
			minIndexInConversationV2: opts.min,
			maxIndexInConversationV2: opts.max,
			direction: opts.direction ?? 0
		});
	}
	/** 冷启动首屏消息（cmd=2043） */
	init(opts = {}) {
		return this.call(PATH$1.init, 2043, "messageByInit", {
			version: opts.version ?? 0,
			page: opts.page ?? 0
		});
	}
	/** 盖楼消息冷启动（cmd=2204） */
	thread(opts = {}) {
		return this.call(PATH$1.thread, 2204, "threadMessageByInit", {
			threadVersion: opts.threadVersion ?? 0,
			threadLimit: opts.threadLimit ?? 20,
			msgLimit: opts.msgLimit ?? 10
		});
	}
	/** 按服务端消息 id 取单条（cmd=211） */
	msg(id, messageId, onlyStatus = false) {
		return this.call(PATH$1.msgById, 211, "getMessageByIdBody", {
			...ref(id),
			serverMessageId: messageId,
			onlyStatus
		});
	}
	/** 按服务端消息 id 批量取（cmd=212） */
	msgs(id, messageIds) {
		return this.call(PATH$1.msgByIds, 212, "getMessagesByServerIdListBody", {
			...ref(id),
			serverMessageIdList: messageIds
		});
	}
	/** 按时间正序翻页取消息（cmd=310） */
	byTime(opts = {}) {
		return this.call(PATH$1.byTime, 310, "getConversationMessagesByTimeBody", {
			convShortId: opts.shortId,
			earliestTimestamp: opts.earliest,
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 20
		});
	}
	/** 消息标记/取消标记（cmd=2036） */
	mark(opts) {
		return this.call(PATH$1.mark, 2036, "markMessageBody", {
			...ref(opts),
			serverMessageId: opts.messageId,
			doAction: opts.action ?? 0,
			actionType: opts.actionType ?? 0,
			sortTime: opts.sortTime,
			tag: opts.tag ?? 0
		});
	}
	/** 修改消息扩展与内容（cmd=2021） */
	modifyExt(opts) {
		return this.call(PATH$1.modifyExt, 2021, "modifyMessageExtBody", {
			...ref(opts),
			messageId: opts.messageId,
			ticket: opts.ticket ?? "",
			ext: opts.ext,
			isEdited: opts.isEdited ?? false,
			content: opts.content,
			messageType: opts.messageType
		});
	}
	/** 控制类消息区间（cmd=12040） */
	cmdRange(opts = {}) {
		return this.call(PATH$1.cmdRange, 12040, "getCmdMessageRangeBody", {
			cmdIndexV2: opts.cmdIndex ?? 0,
			size: opts.size ?? 20,
			direction: opts.direction ?? 0,
			cmdMessageChainV2Index: opts.chainIndex
		});
	}
	/** 指定类型消息列表（cmd=12050） */
	specified(opts) {
		return this.call(PATH$1.specified, 12050, "getConversationSpecifiedMessageListBody", {
			messageListType: opts.listType ?? 0,
			conversationShortId: opts.shortId,
			offset: opts.offset ?? 0,
			count: opts.count ?? 20
		});
	}
	/** 收藏会话列表（cmd=611） */
	favorite(opts = {}) {
		return this.call(PATH$1.favorite, 611, "getConversationInfoListByFavoriteV2Body", {
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 20
		});
	}
	/** 置顶会话列表（cmd=612） */
	top(opts = {}) {
		return this.call(PATH$1.top, 612, "getConversationInfoListByTopV2Body", {
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 20,
			conversationType: opts.type ?? 0
		});
	}
	/** 批量标记已读（cmd=613） */
	batchRead(list) {
		return this.call(PATH$1.batchRead, 613, "batchMarkReadBody", { markReadRequests: list.map((o) => ({
			...ref(o),
			readMessageIndex: o.readIndex,
			readMessageIndexV2: o.readIndexV2,
			convUnreadCount: o.unread,
			totalUnreadCount: o.totalUnread,
			readBadgeCount: o.badge,
			ticket: o.ticket ?? ""
		})) });
	}
	/** 批量删除会话（cmd=619） */
	batchDelete(list) {
		return this.call(PATH$1.batchDelete, 619, "batchDeleteConversationBody", { markDeleteRequests: list.map((o) => ({
			...ref(o),
			lastMessageIndex: o.index,
			lastMessageIndexV2: o.indexV2,
			badgeCount: o.badge
		})) });
	}
	/** 清空会话消息（cmd=620） */
	clearMsg(opts) {
		return this.call(PATH$1.clearMsg, 620, "clearConversationMessageV2Body", {
			...ref(opts),
			lastMessageIndex: opts.index,
			lastMessageIndexV2: opts.indexV2,
			lastMsgBadgeCount: opts.badge
		});
	}
	/** 最近陌生人会话（cmd=12063） */
	recentStrangerConv(opts = {}) {
		return this.call(PATH$1.recentStrangerConv, 12063, "getRecentStrangerConv", {
			maxVersion: opts.max,
			minVersion: opts.min,
			reverse: opts.reverse ?? false,
			source: opts.source ?? ""
		});
	}
	/** 盖楼订阅状态（cmd=2205） */
	threadSub(opts) {
		return this.call(PATH$1.threadSub, 2205, "updateThreadSubscribeStatus", {
			threadId: opts.threadId ?? "",
			threadShortId: opts.threadShortId,
			status: opts.status
		});
	}
	/** 表情回应（cmd=705）：key 以 se:<键值> 下发，幂等命中服务端回 statusCode=1 */
	async react(opts) {
		return this.call("/v1/message/set_property", 705, "modifyMessageProperty", {
			propertyList: [{
				conversationId: opts.conversationId ?? "",
				conversationShortId: opts.shortId,
				conversationType: opts.type ?? 1,
				serverMessageId: opts.messageId,
				clientMessageId: "",
				modifyPropertyContent: [{
					operation: opts.enabled === false ? 1 : 0,
					key: `se:${opts.emoji}`,
					value: "",
					idempotentId: await this.im.uid()
				}]
			}],
			ticket: ""
		}, [0, 1]);
	}
	/** 会话悬浮条是否展示 */
	floatingCheck(query) {
		return rest(this.im, "/aweme/v1/im/conversation/floating_bar/check", {
			host: DOMAIN.social,
			query
		});
	}
	/** 会话悬浮条配置 */
	floatingConfigs(query) {
		return rest(this.im, "/aweme/v1/im/conversation/floating_bar/configs", {
			host: DOMAIN.social,
			query
		});
	}
	/** 默认聊天背景图 */
	backgrounds(query) {
		return rest(this.im, "/aweme/v1/im/conversation/background_pictures/default/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 会话场景信息（v2 路径） */
	scene(query) {
		return rest(this.im, "/aweme/v2/im/conversation/info/other/scene", {
			host: DOMAIN.social,
			query
		});
	}
	/** 会话附加信息 */
	other(body) {
		return rest(this.im, "/aweme/v1/im/conversation/info/other", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 会话内可打开的小程序/应用列表 */
	openApps(body) {
		return rest(this.im, "/aweme/v1/im/conversation/open_app/list", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
};
//#endregion
//#region src/app/account.ts
/** App 账号域：本人/他人主页、各类设置与社交计数 */
var Account = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 本人主页：登录后拿 uid/sec_uid/昵称 */
	self(query) {
		return rest(this.im, "/aweme/v1/user/profile/self/", {
			host: DOMAIN.core,
			query
		});
	}
	/** 他人主页：sec_user_id 是唯一必填标识 */
	other(secUserId, query = {}) {
		return rest(this.im, "/aweme/v1/user/profile/other/", {
			host: DOMAIN.core,
			query: {
				...query,
				sec_user_id: secUserId
			}
		});
	}
	/** 主页场景配置（tab/入口等） */
	scene(query) {
		return rest(this.im, "/aweme/v1/user/profile/scene/", {
			host: DOMAIN.platform,
			query
		});
	}
	/** 个人设置 */
	userSettings(query) {
		return rest(this.im, "/aweme/v1/user/settings/", {
			host: DOMAIN.platform,
			query
		});
	}
	/** 全局设置 */
	settings(query) {
		return rest(this.im, "/aweme/v1/settings/", {
			host: DOMAIN.normal,
			query
		});
	}
	/** 社交关系设置 */
	socialSettings(query) {
		return rest(this.im, "/aweme/v1/social/settings/query/", {
			host: DOMAIN.platform,
			query
		});
	}
	/** 社交计数：真机 body 为 zstd 压缩的表单串 */
	socialCount(body) {
		return rest(this.im, "/aweme/v1/social/count/", {
			host: DOMAIN.platform,
			enc: "zstd-form",
			body
		});
	}
	/** 合规设置 */
	compliance(query) {
		return rest(this.im, "/aweme/v1/compliance/settings/", {
			host: DOMAIN.normal,
			query
		});
	}
	/** 封禁信息 */
	ban(query) {
		return rest(this.im, "/aweme/v1/im/punish/ban_info/", {
			host: DOMAIN.socialLf,
			query
		});
	}
	/** 紧急禁用状态 */
	forbid(query) {
		return rest(this.im, "/aweme/v1/im/punish/emergency_forbid_status/", {
			host: DOMAIN.socialLf,
			query
		});
	}
	/** DX 客户端状态 */
	dx(query) {
		return rest(this.im, "/aweme/v1/im/dx/app/status/", {
			host: DOMAIN.socialLf,
			query
		});
	}
	/** 资料同步提示（头像/昵称待更新红点） */
	syncTips(query) {
		return rest(this.im, "/user/check/show_tips/sync_profile/", {
			host: DOMAIN.normalM,
			query
		});
	}
	/** 隐私图片（平台侧生成/查询） */
	privacyImage(query) {
		return rest(this.im, "/aweme/privacy/build_privacy_image/", {
			host: DOMAIN.platform,
			query
		});
	}
};
//#endregion
//#region src/app/notice.ts
/** App 通知域：未读汇总与通知列表 */
var Notice = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 各分类未读数 */
	count(query) {
		return rest(this.im, "/aweme/v1/notice/count/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 通知列表 */
	list(query) {
		return rest(this.im, "/aweme/v1/notice/multi/", {
			host: DOMAIN.social,
			query
		});
	}
};
//#endregion
//#region src/app/friend.ts
/** App 好友域：推荐、好友申请列表与审批 */
const PATH = {
	applies: "/v1/friend/get_receive_apply_list",
	reply: "/v1/friend/reply_apply"
};
var Friend = class {
	im;
	dev;
	ids;
	constructor(im, dev, ids) {
		this.im = im;
		this.dev = dev;
		this.ids = ids;
	}
	/** 可能认识的人 */
	recommend(query) {
		return rest(this.im, "/aweme/v1/im/user/friend/recommend/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 推荐候选 topK */
	topk(query) {
		return rest(this.im, "/aweme/v1/im/user/friend/topk/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 新推荐用户数量（红点） */
	recommendCount(query) {
		return rest(this.im, "/aweme/v2/new/recommend/user/count/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 收到的好友申请（cmd=2048），游标由调用方翻页 */
	applies(opts = {}) {
		return pbQuery(this.im, this.dev, this.ids, PATH.applies, 2048, "getFriendReceiveApplyList", {
			cursor: opts.cursor ?? 0,
			limit: opts.limit ?? 100,
			getTotalCount: true,
			status: opts.status ?? 0
		});
	}
	/** 审批好友申请（cmd=2049）：attitude 1 通过 / 2 拒绝 */
	reply(uids, attitude) {
		return pbQuery(this.im, this.dev, this.ids, PATH.reply, 2049, "replyFriendApply", {
			userId: uids,
			attitude,
			ext: {}
		});
	}
};
//#endregion
//#region src/app/resource.ts
/** App 资源域：表情、贴纸、收藏文件与好友相册 */
var Resource = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 资源位聚合（入口/面板配置） */
	resources(query) {
		return rest(this.im, "/aweme/v1/im/resources/list/aggregation/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 表情资源 */
	emoji(query) {
		return rest(this.im, "/aweme/v1/im/resources/emoji/", {
			host: DOMAIN.normal3,
			query
		});
	}
	/** 表情搜索 */
	emoticon(query) {
		return rest(this.im, "/aweme/v1/im/resources/emoticon/search", {
			host: DOMAIN.socialLf,
			query
		});
	}
	/** 打招呼贴纸 */
	helloSticker(query) {
		return rest(this.im, "/aweme/v1/im/resources/hellosticker/", {
			host: DOMAIN.socialLf,
			query
		});
	}
	/** 收藏文件 */
	collectFile(query) {
		return rest(this.im, "/aweme/v1/im/collect_file/get", {
			host: DOMAIN.social,
			query
		});
	}
	/** 好友相册列表 */
	album(query) {
		return rest(this.im, "/aweme/v1/im/friend_album/media/get", {
			host: DOMAIN.social,
			query
		});
	}
	/** 批量加入好友相册 */
	albumAdd(body) {
		return rest(this.im, "/aweme/v1/im/friend_album/media/multi_add", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 上传通道配置（分片大小/域名，上传前先取） */
	uploadConfig(query) {
		return rest(this.im, "/aweme/v1/im/upload/config/v2", {
			host: DOMAIN.social,
			query
		});
	}
};
//#endregion
//#region src/app/social.ts
/** App 社交域：关系推荐、常看、附近的人与用户中心 */
var Social = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 关注关系下的推荐 */
	spotlight(query) {
		return rest(this.im, "/aweme/v1/spotlight/relation/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 熟人设置 */
	familiar(query) {
		return rest(this.im, "/aweme/v1/social/familiar/settings/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 用户推荐（与好友域的 friend/recommend 是两个接口） */
	recommend(body) {
		return rest(this.im, "/aweme/v2/user/recommend", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 本地通讯录用户 */
	localUsers(query) {
		return rest(this.im, "/aweme/v1/local/user/list/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 用户中心聚合数据 */
	center(body) {
		return rest(this.im, "/aweme/v2/user/center/get", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 用户中心计划 */
	centerPlan(body) {
		return rest(this.im, "/aweme/v2/user/center/plan", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 用户中心同步 */
	centerSync(body) {
		return rest(this.im, "/aweme/v2/user/center/sync", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 用户中心消息同步 */
	centerMsgs(body) {
		return rest(this.im, "/aweme/v2/user/center/sync/msgs", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 熟人视频访客列表 */
	visitors(query) {
		return rest(this.im, "/aweme/v1/familiar/video/visitor/list/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 熟人视频统计上报 */
	videoStats(body) {
		return rest(this.im, "/aweme/v1/familiar/video/stats/", {
			host: DOMAIN.socialLf,
			enc: "json",
			body
		});
	}
	/** VoIP 冷启动拉取 */
	voipColdPull(query) {
		return rest(this.im, "/aweme/janus/im/voip/cold_pull/v1/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 收藏的用户列表 */
	collectUsers(query) {
		return rest(this.im, "/aweme/v1/collect/user/list/", {
			host: DOMAIN.platformM,
			query
		});
	}
};
//#endregion
//#region src/app/group.ts
/** App 群域：群列表、指标、活跃信息、群资料与可见范围 */
var Group = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 我加入的群列表 */
	groups(query) {
		return rest(this.im, "/aweme/v1/im/group/list/self/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群指标（body: conversation_short_id / periods / indicator_types 均必填） */
	indicators(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/get_group_indicators", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 区间内群聊链条 */
	chains(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/group_chains_by_range/get", {
			host: DOMAIN.social,
			enc: "form",
			body
		});
	}
	/** 按群 id 取链条（与区间版同形，参数换成 group_id） */
	chain(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/group_chains_by_id/get", {
			host: DOMAIN.social,
			enc: "form",
			body
		});
	}
	/** 群打卡信息（body: group_id） */
	checkin(body) {
		return rest(this.im, "/interest/checkin/conversation/info/get", {
			host: DOMAIN.platform,
			enc: "json",
			body
		});
	}
	/** 群打卡权限校验（body: conversation_id 传短 id 字符串） */
	checkinAuth(body) {
		return rest(this.im, "/interest/checkin/conversation/auth/check", {
			host: DOMAIN.platform,
			enc: "json",
			body
		});
	}
	/** 成员设置更新 */
	memberSettings(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/member_settings/update", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 群操作扫描 */
	scan(query) {
		return rest(this.im, "/aweme/v1/im/group_v2/operation/scan", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群标签扫描（query: conv_short_id / cursor / limit / choose，choose 如 active_info_item） */
	tags(query) {
		return rest(this.im, "/aweme/v1/im/group_v2/tag/scan", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群活跃信息（body 需 group_id + with_active_info/with_fans_info/with_common_label_info 全为 1） */
	active(body) {
		return rest(this.im, "/aweme/v1/im/group/active_info/get", {
			host: DOMAIN.social,
			enc: "zstd-form",
			body
		});
	}
	/** 群活跃信息扫描 */
	activeScan(query) {
		return rest(this.im, "/aweme/v1/im/group/active_info/scan", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群号 */
	number(shortId) {
		return rest(this.im, "/aweme/v1/im/group/get_group_number/", {
			host: DOMAIN.social,
			enc: "form",
			body: { conversation_short_id: String(shortId) }
		});
	}
	/** 群资料更新 */
	updateGroup(body) {
		return rest(this.im, "/aweme/v1/im/group/update", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 设置用户的群可见列表 */
	visible(body) {
		return rest(this.im, "/aweme/v1/im/group/set_user_group_list/", {
			host: DOMAIN.social,
			enc: "form",
			body
		});
	}
	/** 群合照样式 */
	mixPhoto(query) {
		return rest(this.im, "/aweme/v1/im/group_v2/mix_photo_style/get", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群资料校验 */
	validate(query) {
		return rest(this.im, "/aweme/v1/im/group/validate_info", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群升级信息 */
	upgrade(query) {
		return rest(this.im, "/aweme/v1/im/group/upgrade_info", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群升级信息列表 */
	upgrades(query) {
		return rest(this.im, "/aweme/v1/im/group/upgrade_info_list/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 推荐折叠群 */
	foldGroups(query) {
		return rest(this.im, "/aweme/v1/im/group_v2/recom_fold_groups", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群任务列表（query: group_id / scene，scene 取值如 upgrade_public_group） */
	tasks(query) {
		return rest(this.im, "/aweme/v1/im/group_v2/group_task/list", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群任务更新 */
	taskUpdate(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/group_task/update", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 群操作批量校验 */
	multiCheck(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/action/multi_check", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 入群门槛设置 */
	entryLimit(query) {
		return rest(this.im, "/aweme/v1/im/group/settings/entry_limit/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群聊词库设置 */
	words(query) {
		return rest(this.im, "/aweme/v1/im/group/settings/words/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 群广场热点（body: source / existing_hotspot_ids / biz_ext） */
	hotspot(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/distribution/hotspot/", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 群广场推荐（body: source / existing_group_ids / biz_ext） */
	recommend(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/distribution/recommend", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 群广场信息 */
	square(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/distribution/square_info/", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 群广场搜索（body: source / query / cursor / limit / biz_ext） */
	searchGroups(body) {
		return rest(this.im, "/aweme/v1/im/group_v2/distribution/search", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 群操作前置校验 */
	actionCheck(query) {
		return rest(this.im, "/aweme/v1/im/group_v2/action/check", {
			host: DOMAIN.social,
			query
		});
	}
	/** 按群 id 批量取群（group_ids 逗号串） */
	others(query) {
		return rest(this.im, "/aweme/v1/im/group/list/other/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 建群面板信息 */
	panel(query) {
		return rest(this.im, "/aweme/v1/im/group_v2/creation_panel_info/get", {
			host: DOMAIN.social,
			query
		});
	}
	/** 可邀请的粉丝列表（query: limit / scene，scene=0 才返回 fans_list） */
	fansList(query) {
		return rest(this.im, "/aweme/v1/im/group/invite/fans_list", {
			host: DOMAIN.social,
			query
		});
	}
	/** 粉丝群卡片状态（query: from / to_sec_uid / is_new_style） */
	fansCard(query) {
		return rest(this.im, "/aweme/v1/im/group/get_fans_group_card/", {
			host: DOMAIN.social,
			query
		});
	}
};
//#endregion
//#region src/app/config.ts
/** App IM 配置域：全局配置、策略、活跃状态与会话入口上报 */
var Config = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 客户端 IM 配置 */
	base(query) {
		return rest(this.im, "/aweme/v1/im/config/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 服务端全局配置 */
	global(query) {
		return rest(this.im, "/aweme/v1/im/service/config/global/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 策略配置 */
	strategy(query) {
		return rest(this.im, "/aweme/v1/im/strategy/config/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 重启降级配置 */
	reboot(query) {
		return rest(this.im, "/aweme/v1/im/reboot/misc/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 用户活跃配置 */
	active(query) {
		return rest(this.im, "/aweme/v1/im/user/active/config/get", {
			host: DOMAIN.social,
			query
		});
	}
	/** 用户活跃心跳更新 */
	activeUpdate(query) {
		return rest(this.im, "/aweme/v1/im/user/active/update/", {
			host: DOMAIN.social,
			query
		});
	}
	/** 上报用户活跃状态（表单） */
	activeStatus(body) {
		return rest(this.im, "/aweme/v1/im/user/active/status/", {
			host: DOMAIN.social,
			enc: "form",
			body
		});
	}
	/** 进入会话上报 */
	enterChat(body) {
		return rest(this.im, "/aweme/v1/im/service/enter_chat/", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 进入消息 Tab 上报 */
	msgTabEnter(body) {
		return rest(this.im, "/aweme/v1/im/service/msg_tab/enter", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
};
//#endregion
//#region src/app/growth.ts
/** App 成长域：连续聊天、火焰成就与音频模型等增长类接口 */
var Growth = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 连续聊天关系成就 */
	consecutive(query) {
		return rest(this.im, "/aweme/v1/im/growth/consecutive_chat/relation_achieve", {
			host: DOMAIN.social,
			query
		});
	}
	/** 成长分享列表 */
	shareList(body) {
		return rest(this.im, "/aweme/v1/im/growth/share/list", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 连续聊天开关 */
	switch(body) {
		return rest(this.im, "/aweme/v1/im/growth/consecutive_switch/set/", {
			host: DOMAIN.socialLf,
			enc: "json",
			body
		});
	}
	/** 连续聊天上报 */
	report(body) {
		return rest(this.im, "/aweme/v1/im_communication/consecutive_chat/report/", {
			host: DOMAIN.socialLf,
			enc: "zstd-json",
			body
		});
	}
	/** 动态策略 */
	dynamic(body) {
		return rest(this.im, "/aweme/v1/im_communication/strategy/dynamic/", {
			host: DOMAIN.socialLf,
			enc: "zstd-json",
			body
		});
	}
	/** 语音识别模型配置 */
	audioModel(query) {
		return rest(this.im, "/aweme/v1/im_communication/audio/model_config/", {
			host: DOMAIN.socialLf,
			query
		});
	}
	/** 火焰成就 */
	flame(query) {
		return rest(this.im, "/aweme/v1/im_communication/flame_achieve/get/", {
			host: DOMAIN.socialLf,
			query
		});
	}
};
//#endregion
//#region src/app/chatai.ts
/** App 聊天智能域：Gaga、宠物精灵与子弹事件 */
var ChatAi = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** Gaga 聚合信息 */
	gaga(body) {
		return rest(this.im, "/aweme/v1/im/chatai/gagas/aggr_info", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 宠物聚合信息 */
	pet(body) {
		return rest(this.im, "/aweme/v1/im/chatai/pet/aggr_info/", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 宠物精灵邀请卡 */
	petCard(query) {
		return rest(this.im, "/aweme/v1/im_communication/pet_elf/invite_card/get/", {
			host: DOMAIN.socialLf,
			query
		});
	}
	/** 子弹事件请求并更新 */
	bullet(body) {
		return rest(this.im, "/aweme/v1/im/bullet/common_event/request_and_update", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 子弹事件数据提交 */
	bulletSubmit(body) {
		return rest(this.im, "/aweme/v1/im/bullet/common_event/submit_data", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
};
//#endregion
//#region src/app/comm.ts
/** App 通信域：实验命中、合并消息卡与杂项上报 */
var Comm = class {
	im;
	constructor(im) {
		this.im = im;
	}
	/** 实验命中查询 */
	expHit(body) {
		return rest(this.im, "/aweme/v1/im_communication/exp_hit/query/", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
	/** 合并消息卡准备 */
	mergePrepare(body) {
		return rest(this.im, "/aweme/v1/im_communication/merge_msg_card/prepare/", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 杂项上报 */
	misc(body) {
		return rest(this.im, "/aweme/v1/im_communication/misc/", {
			host: DOMAIN.social,
			enc: "zstd-json",
			body
		});
	}
	/** 分享上报 */
	shareReport(body) {
		return rest(this.im, "/aweme/v1/im_communication/share_report/", {
			host: DOMAIN.social,
			enc: "json",
			body
		});
	}
};
//#endregion
//#region src/app/media.ts
/** App 发送前媒体归一化：cookie 通道上传输入源，产出资产供 wire 组装 */
var Media = class {
	im;
	auth;
	constructor(im, auth) {
		this.im = im;
		this.auth = auth;
	}
	/** App 网关不代传媒体；上传链路复用登录 cookie，每次取最新会话避免 token 轮换后失效 */
	async prepare(body) {
		if (body.type !== "image" && body.type !== "video" && body.type !== "file") return body;
		const uid = await this.im.uid();
		const up = new Uploader(new Http({
			cookie: this.auth.cookie(),
			userId: uid
		}), uid);
		if (body.type === "image") {
			if (!isInput(body.image)) return body;
			return {
				...body,
				image: await up.uploadImage(await resolveMedia(body.image))
			};
		}
		if (body.type === "file") {
			const file = body.file;
			if (!("source" in file)) return body;
			return {
				...body,
				file: { asset: await up.uploadFile(await resolveMedia(file.source), file.name ?? fileNameOf(file.source)) }
			};
		}
		const video = body.video;
		if (!("source" in video)) return body;
		const bytes = await resolveMedia(video.source);
		const dims = await probeVideo(bytes);
		let width = video.width ?? dims.width;
		let height = video.height ?? dims.height;
		let poster = video.poster;
		if (poster === void 0) {
			const shot = await extractVideoPoster(bytes);
			poster = await up.uploadImage(shot.jpeg);
			width ||= shot.width;
			height ||= shot.height;
		} else if (isInput(poster)) poster = await up.uploadImage(await resolveMedia(poster));
		return {
			...body,
			video: {
				asset: await up.uploadVideo(bytes),
				poster,
				width,
				height
			}
		};
	}
};
//#endregion
//#region src/app/send.ts
/** App 发送编排：媒体先归一化，合并转发先注册云端记录，再交给 IM 帧发送 */
var Send = class {
	conv;
	media;
	comm;
	constructor(conv, media, comm) {
		this.conv = conv;
		this.media = media;
		this.comm = comm;
	}
	async send(opts) {
		const body = opts.body;
		if (body?.type === "forward") return this.forward(opts, body.nodes);
		return this.conv.send({
			...opts,
			body: body ? await this.media.prepare(body) : void 0
		});
	}
	/** 合并转发：真实节点走 prepare 注册原消息，伪造节点直接发摘要卡（无云端记录可注册） */
	async forward(opts, nodes) {
		if (!nodes.length) return err({ nodes });
		if (opts.shortId === void 0) return err({ shortId: opts.shortId });
		const generated = mergeContent(nodes, opts.shortId);
		if (nodes.some((node) => node.msgId === void 0)) return this.conv.send({
			...opts,
			body: void 0,
			messageType: 136,
			content: generated
		});
		const content = (await this.comm.mergePrepare(rawJson({
			origin_conv_short_id: BigInt(opts.shortId),
			msg_id_list: nodes.map((node) => BigInt(node.msgId)),
			generated_content: generated
		})))["verified_content"];
		return this.conv.send({
			...opts,
			body: void 0,
			messageType: 136,
			content: typeof content === "string" ? content : generated
		});
	}
};
//#endregion
//#region src/app/app.ts
/** bot.app：设备注册、App 登录与 IM 加密通道的两级门面 */
/** 扫码轮询间隔：与真机一致 2s，过快会被服务端按 2156/7「系统繁忙」限流 */
const QR_POLL = 2e3;
/** 上行短信轮询：等用户发短信 */
const UP_POLL = 2e3;
const UP_TRIES = 30;
/** 一次决策失败后重发登录取新决策的轮数；5014 属环境判定，不在本循环内硬试 */
const SLIDE_TRIES = 3;
var App = class {
	dev;
	ids;
	auth;
	log;
	flow;
	agent;
	convBot;
	accountBot;
	noticeBot;
	friendBot;
	resourceBot;
	socialBot;
	groupBot;
	configBot;
	growthBot;
	chatAiBot;
	commBot;
	mediaBot;
	sendBot;
	recvBot;
	constructor(opts = {}) {
		this.dev = {
			...DEV,
			...opts.dev
		};
		this.ids = fill(opts.ids);
		this.auth = new Auth([this.ids.cookie, opts.cookie].filter(Boolean).join("; "));
		this.log = opts.log ?? createLog({ tag: "app" });
	}
	/** 注册并激活新设备（结果由调用方持久化后回传） */
	async device(opts = {}) {
		if (!opts.force && this.ids.device_id) {
			if (!await activate(this.ids, { host: opts.host })) this.log.warn("设备激活失败，继续使用原设备");
			this.log.info("设备已激活");
			return this.ids;
		}
		if (opts.force) this.auth.reset();
		Object.assign(this.ids, fill({ first_install: this.ids.first_install }));
		const next = await device(this.ids, { host: opts.host });
		Object.assign(this.ids, next);
		this.auth.jar.merge(next.cookie ?? "");
		this.log.info(`设备注册成功 device_id=${next.device_id}`);
		return this.ids;
	}
	/** 仅发送验证码；1105 时返回 captcha 交给调用方处理 */
	async code(mobile, cred = {}) {
		const f = this.begin(mobile);
		const data = await f.sendCode(cred);
		return {
			sent: Number(data.error_code) === 0,
			data,
			captcha: read(f.last)
		};
	}
	/** 为当前 1105 挑战起本地验证页；手机扫码拖动通过后 wait() 完成，再回填票据重发 */
	async slide(opts = {}) {
		const ch = read(this.login.last);
		if (!ch) throw new Error("当前没有滑块挑战，请先发送验证码");
		return serve({
			challenge: ch,
			dev: this.dev,
			ids: this.ids,
			auth: this.auth,
			...opts
		});
	}
	/** 验证码登录（含 1105 重试与 2046 二次验证） */
	async sms(opts) {
		const f = this.begin(opts.mobile);
		const sent = await this.retry((c) => f.sendCode(c), opts, "tt_send_sms_login");
		if (Number(sent.error_code) !== 0) return this.res(sent);
		const code = opts.code ?? (opts.onCode ? await opts.onCode() : "");
		if (!code) return this.res(sent);
		return this.finish(await f.smsLogin(code), opts);
	}
	/** 密码登录（含 1105 重试与 2046 二次验证） */
	async pwd(opts) {
		const f = this.begin(opts.mobile);
		const data = await this.retry((c) => f.pwdLogin(opts.password, void 0, c), opts, "tt_mobile_pwd_login");
		return this.finish(data, opts);
	}
	/** 扫码登录（含二次验证：验证完成后重放 check_qrconnect） */
	async qr(opts = {}) {
		let data = {};
		let auth = new Auth();
		for (let round = 0; round < 3; round++) {
			auth = new Auth();
			const f = this.begin("", auth);
			const code = await f.qrGetCode();
			const index = String(code.qrcode_index_url ?? "");
			const raw = String(code.qrcode ?? "");
			if (Number(code.error_code) !== 0 || !index && !raw) return this.res(code);
			const url = index || (raw.startsWith("http") ? raw : "");
			const base64 = raw && !raw.startsWith("http") ? raw : void 0;
			await opts.onQr?.({
				url,
				base64
			});
			const token = String(code.token ?? "");
			if (!token) return this.res(code);
			data = code;
			let last = "";
			let refresh = false;
			const expire = Number(code.expire_time ?? 0) * 1e3;
			for (let i = 0; i < 120; i++) {
				await sleep$1(QR_POLL);
				if (expire && Date.now() > expire - 5e3) {
					refresh = true;
					break;
				}
				data = await f.qrCheck(token);
				const st = String(data.status ?? "");
				const ec = Number(data.error_code ?? 0);
				if (`${st}|${ec}` !== last) {
					last = `${st}|${ec}`;
					await opts.onStatus?.(st, ec);
				}
				if (ec === 2046) break;
				if (ec > 0) return this.res(data);
				if (st === "confirmed") break;
				if (st === "expired" || st === "canceled") return this.res(data);
			}
			if (!refresh) break;
		}
		const res = await this.finish(data, opts);
		if (auth.jar.get("sessionid")) {
			this.auth.jar.merge(auth.cookie());
			return {
				...res,
				ok: true,
				cookie: this.auth.cookie()
			};
		}
		return res;
	}
	/** 手动提交二次验证（未给 onMfa 回调时使用）：kind=sms/password/upsms */
	async mfa(kind, input = "") {
		const f = this.login;
		const data = kind === "password" ? await f.accountVerify(input) : kind === "sms" ? await f.validateCode(input) : kind === "upsms" ? await f.upSmsVerify() : await f.mfaQrCheck(input);
		if (Number(data.error_code ?? 0) !== 0 || !f.waiting) return this.finish(data, {});
		return this.finish(await f.replayLogin(), {});
	}
	/** 账号信息（需已登录 Cookie） */
	async info() {
		return this.login.accountInfo();
	}
	/** 当前登录态 */
	token() {
		return {
			cookie: this.auth.cookie(),
			userId: this.auth.jar.get("uid") ?? void 0
		};
	}
	/** 订阅 App 推送事件：事件名与 bot.on 一致，来源是 App Frontier 长连接 */
	on(event, fn) {
		this.recv.on(event, fn);
	}
	/** 建立 App Frontier 长连接（需已登录，握手带 X-Tt-Token） */
	start() {
		return this.recv.start();
	}
	stop() {
		this.recvBot?.stop();
	}
	get connected() {
		return this.recvBot?.connected ?? false;
	}
	/** 关闭/开启「保存登录信息」 */
	async record(status) {
		return this.login.record(status);
	}
	/** keyhub 握手结果（IM 加密密钥） */
	async key() {
		const s = await this.agentOf().key();
		return {
			ticket: s.ticket,
			key: s.keyIM.toString("base64"),
			expiresAt: s.expiresAt
		};
	}
	/** 调用 IM 接口（默认按端点表加密 pb） */
	async im(call = {}) {
		return this.agentOf().call(call);
	}
	/** 导出 ee.info 96B key 包，供外部进程复用 IM 会话 */
	async ee(id) {
		const agent = this.agentOf();
		return eeEntry(await agent.key(), id ?? `${await agent.uid()}+IM`);
	}
	/** 会话列表（pb cmd=2006） */
	convList(opts = {}) {
		return this.conv.list(opts);
	}
	/** 批量会话详情（pb cmd=610） */
	convInfos(list) {
		return this.conv.infos(list);
	}
	/** 单个会话详情（pb cmd=608） */
	convInfo(id) {
		return this.conv.info(id);
	}
	/** 历史消息（pb cmd=301） */
	history(opts) {
		return this.conv.history(opts);
	}
	/** 标记已读（pb cmd=2002） */
	read(opts) {
		return this.conv.read(opts);
	}
	/** 成员已读游标（pb cmd=2000） */
	readIndex(id) {
		return this.conv.readIndex(id);
	}
	/** 最小同步游标（pb cmd=2001） */
	minIndex(id) {
		return this.conv.minIndex(id);
	}
	/** 消息索引统计（pb cmd=12048） */
	userMessage(opts = {}) {
		return this.conv.userMessage(opts);
	}
	/** 发送消息（pb cmd=100）；媒体输入源自动上传，forward 走 App 域注册 */
	send(opts) {
		return this.sender.send(opts);
	}
	/** 表情回应（pb cmd=705）；emoji 传键值如 [爱心]，false 取消 */
	react(opts) {
		return this.conv.react(opts);
	}
	/** 创建会话（pb cmd=609） */
	createConv(opts) {
		return this.conv.create(opts);
	}
	/** 陌生人会话列表（pb cmd=1001） */
	strangerList(opts = {}) {
		return this.conv.strangerList(opts);
	}
	/** 会话审核列表（pb cmd=2027） */
	auditList(opts = {}) {
		return this.conv.auditList(opts);
	}
	/** 批量查成员已读游标（pb cmd=2038） */
	participantsReadIndex(id) {
		return this.conv.participantsReadIndex(id);
	}
	/** 最近陌生人消息（pb cmd=12047） */
	recentStranger(opts = {}) {
		return this.conv.recentStranger(opts);
	}
	/** 会话参与者分页（pb cmd=605） */
	participants(opts = {}) {
		return this.conv.participants(opts);
	}
	/** 会话成员列表（pb cmd=12060） */
	members(opts = {}) {
		return this.conv.members(opts);
	}
	/** 批量取多个会话成员（pb cmd=12061） */
	membersBatch(list) {
		return this.conv.membersBatch(list);
	}
	/** 按 uid 精确取成员（pb cmd=654） */
	membersByUid(id, users) {
		return this.conv.membersByUid(id, users);
	}
	/** 按标记位增量拉消息（pb cmd=2037） */
	marks(opts = {}) {
		return this.conv.marks(opts);
	}
	/** 最近控制类消息会话（pb cmd=12062） */
	cmds(opts = {}) {
		return this.conv.cmds(opts);
	}
	/** 会话内控制类消息（pb cmd=2040） */
	cmdMessages(opts = {}) {
		return this.conv.cmdMessages(opts);
	}
	/** 会话内 v2 索引区间消息（pb cmd=2041） */
	msgRange(opts) {
		return this.conv.range(opts);
	}
	/** 冷启动首屏消息（pb cmd=2043） */
	msgInit(opts = {}) {
		return this.conv.init(opts);
	}
	/** 盖楼消息冷启动（pb cmd=2204） */
	threadInit(opts = {}) {
		return this.conv.thread(opts);
	}
	/** 按服务端消息 id 取单条（pb cmd=211） */
	msg(id, messageId, onlyStatus = false) {
		return this.conv.msg(id, messageId, onlyStatus);
	}
	/** 按服务端消息 id 批量取（pb cmd=212） */
	msgs(id, messageIds) {
		return this.conv.msgs(id, messageIds);
	}
	/** 按时间翻页取消息（pb cmd=310） */
	byTime(opts = {}) {
		return this.conv.byTime(opts);
	}
	/** 消息标记/取消标记（pb cmd=2036） */
	mark(opts) {
		return this.conv.mark(opts);
	}
	/** 修改消息扩展与内容（pb cmd=2021） */
	modifyExt(opts) {
		return this.conv.modifyExt(opts);
	}
	/** 控制类消息区间（pb cmd=12040） */
	cmdRange(opts = {}) {
		return this.conv.cmdRange(opts);
	}
	/** 指定类型消息列表（pb cmd=12050） */
	specified(opts) {
		return this.conv.specified(opts);
	}
	/** 收藏会话列表（pb cmd=611） */
	favorite(opts = {}) {
		return this.conv.favorite(opts);
	}
	/** 置顶会话列表（pb cmd=612） */
	top(opts = {}) {
		return this.conv.top(opts);
	}
	/** 批量标记已读（pb cmd=613） */
	batchRead(list) {
		return this.conv.batchRead(list);
	}
	/** 批量删除会话（pb cmd=619） */
	batchDelete(list) {
		return this.conv.batchDelete(list);
	}
	/** 清空会话消息（pb cmd=620） */
	clearMsg(opts) {
		return this.conv.clearMsg(opts);
	}
	/** 最近陌生人会话（pb cmd=12063） */
	recentStrangerConv(opts = {}) {
		return this.conv.recentStrangerConv(opts);
	}
	/** 盖楼订阅状态（pb cmd=2205） */
	threadSub(opts) {
		return this.conv.threadSub(opts);
	}
	/** 本人主页 */
	self(query) {
		return this.account.self(query);
	}
	/** 他人主页（sec_user_id） */
	other(secUserId, query) {
		return this.account.other(secUserId, query);
	}
	/** 主页场景配置 */
	scene(query) {
		return this.account.scene(query);
	}
	/** 个人设置 */
	userSettings(query) {
		return this.account.userSettings(query);
	}
	/** 全局设置 */
	settings(query) {
		return this.account.settings(query);
	}
	/** 社交关系设置 */
	socialSettings(query) {
		return this.account.socialSettings(query);
	}
	/** 社交计数（zstd-form） */
	socialCount(body) {
		return this.account.socialCount(body);
	}
	/** 合规设置 */
	compliance(query) {
		return this.account.compliance(query);
	}
	/** 封禁信息 */
	ban(query) {
		return this.account.ban(query);
	}
	/** 紧急禁用状态 */
	forbid(query) {
		return this.account.forbid(query);
	}
	/** DX 状态 */
	dx(query) {
		return this.account.dx(query);
	}
	/** 资料同步提示 */
	syncTips(query) {
		return this.account.syncTips(query);
	}
	/** 隐私图片 */
	privacyImage(query) {
		return this.account.privacyImage(query);
	}
	/** 通知未读数 */
	noticeCount(query) {
		return this.notice.count(query);
	}
	/** 通知列表 */
	noticeList(query) {
		return this.notice.list(query);
	}
	/** 好友推荐 */
	recommend(query) {
		return this.friend.recommend(query);
	}
	/** 推荐候选 topK */
	topk(query) {
		return this.friend.topk(query);
	}
	/** 新推荐用户数量 */
	recommendCount(query) {
		return this.friend.recommendCount(query);
	}
	/** 收到的好友申请（pb cmd=2048） */
	applies(opts = {}) {
		return this.friend.applies(opts);
	}
	/** 熟人视频访客列表 */
	visitors(query) {
		return this.social.visitors(query);
	}
	/** 熟人视频统计上报 */
	videoStats(body) {
		return this.social.videoStats(body);
	}
	/** VoIP 冷启动拉取 */
	voipColdPull(query) {
		return this.social.voipColdPull(query);
	}
	/** 收藏的用户列表 */
	collectUsers(query) {
		return this.social.collectUsers(query);
	}
	/** 审批好友申请（pb cmd=2049） */
	replyFriend(uids, attitude) {
		return this.friend.reply(uids, attitude);
	}
	/** 资源位聚合 */
	resources(query) {
		return this.resource.resources(query);
	}
	/** 表情资源 */
	emoji(query) {
		return this.resource.emoji(query);
	}
	/** 表情搜索 */
	emoticon(query) {
		return this.resource.emoticon(query);
	}
	/** 打招呼贴纸 */
	helloSticker(query) {
		return this.resource.helloSticker(query);
	}
	/** 上传通道配置 */
	uploadConfig(query) {
		return this.resource.uploadConfig(query);
	}
	/** 收藏文件 */
	collectFile(query) {
		return this.resource.collectFile(query);
	}
	/** 好友相册列表 */
	album(query) {
		return this.resource.album(query);
	}
	/** 批量加入好友相册 */
	albumAdd(body) {
		return this.resource.albumAdd(body);
	}
	/** 关注关系推荐 */
	spotlight(query) {
		return this.social.spotlight(query);
	}
	/** 熟人设置 */
	familiar(query) {
		return this.social.familiar(query);
	}
	/** 用户推荐 */
	userRecommend(body) {
		return this.social.recommend(body);
	}
	/** 本地通讯录用户 */
	localUsers(query) {
		return this.social.localUsers(query);
	}
	/** 用户中心聚合 */
	center(body) {
		return this.social.center(body);
	}
	/** 用户中心计划 */
	centerPlan(body) {
		return this.social.centerPlan(body);
	}
	/** 用户中心同步 */
	centerSync(body) {
		return this.social.centerSync(body);
	}
	/** 用户中心消息同步 */
	centerMsgs(body) {
		return this.social.centerMsgs(body);
	}
	/** 我加入的群列表 */
	groups(query) {
		return this.group.groups(query);
	}
	/** 群指标 */
	indicators(body) {
		return this.group.indicators(body);
	}
	/** 区间群聊链条 */
	chains(body) {
		return this.group.chains(body);
	}
	/** 按群 id 取链条 */
	chain(body) {
		return this.group.chain(body);
	}
	/** 群打卡信息 */
	checkin(body) {
		return this.group.checkin(body);
	}
	/** 群打卡权限校验 */
	checkinAuth(body) {
		return this.group.checkinAuth(body);
	}
	/** 成员设置更新 */
	memberSettings(body) {
		return this.group.memberSettings(body);
	}
	/** 群操作扫描 */
	groupScan(query) {
		return this.group.scan(query);
	}
	/** 群标签扫描 */
	groupTags(query) {
		return this.group.tags(query);
	}
	/** 群活跃信息 */
	active(body) {
		return this.group.active(body);
	}
	/** 群活跃信息扫描 */
	activeScan(query) {
		return this.group.activeScan(query);
	}
	/** 群号 */
	groupNumber(shortId) {
		return this.group.number(shortId);
	}
	/** 群资料更新 */
	updateGroup(body) {
		return this.group.updateGroup(body);
	}
	/** 群可见范围 */
	visible(body) {
		return this.group.visible(body);
	}
	/** 群合照样式 */
	mixPhoto(query) {
		return this.group.mixPhoto(query);
	}
	/** 群资料校验 */
	validate(query) {
		return this.group.validate(query);
	}
	/** 群升级信息 */
	upgrade(query) {
		return this.group.upgrade(query);
	}
	/** 群升级信息列表 */
	upgrades(query) {
		return this.group.upgrades(query);
	}
	/** 会话悬浮条是否展示 */
	floatingCheck(query) {
		return this.conv.floatingCheck(query);
	}
	/** 会话悬浮条配置 */
	floatingConfigs(query) {
		return this.conv.floatingConfigs(query);
	}
	/** 默认聊天背景图 */
	backgrounds(query) {
		return this.conv.backgrounds(query);
	}
	/** 会话场景信息 */
	convScene(query) {
		return this.conv.scene(query);
	}
	/** 会话附加信息 */
	convOther(body) {
		return this.conv.other(body);
	}
	/** 会话可打开应用列表 */
	openApps(body) {
		return this.conv.openApps(body);
	}
	/** 推荐折叠群 */
	foldGroups(query) {
		return this.group.foldGroups(query);
	}
	/** 群任务列表 */
	groupTasks(query) {
		return this.group.tasks(query);
	}
	/** 群任务更新 */
	groupTaskUpdate(body) {
		return this.group.taskUpdate(body);
	}
	/** 群操作批量校验 */
	groupMultiCheck(body) {
		return this.group.multiCheck(body);
	}
	/** 入群门槛设置 */
	entryLimit(query) {
		return this.group.entryLimit(query);
	}
	/** 群聊词库设置 */
	groupWords(query) {
		return this.group.words(query);
	}
	/** 群广场热点 */
	groupHotspot(body) {
		return this.group.hotspot(body);
	}
	/** 群广场推荐 */
	groupRecommend(body) {
		return this.group.recommend(body);
	}
	/** 群广场信息 */
	groupSquare(body) {
		return this.group.square(body);
	}
	/** 群广场搜索 */
	groupSearch(body) {
		return this.group.searchGroups(body);
	}
	/** 群操作前置校验 */
	groupActionCheck(query) {
		return this.group.actionCheck(query);
	}
	/** 按群 id 批量取群 */
	groupOthers(query) {
		return this.group.others(query);
	}
	/** 建群面板信息 */
	groupPanel(query) {
		return this.group.panel(query);
	}
	/** 可邀请的粉丝列表 */
	groupFansList(query) {
		return this.group.fansList(query);
	}
	/** 粉丝群卡片状态 */
	groupFansCard(query) {
		return this.group.fansCard(query);
	}
	/** 客户端 IM 配置 */
	imConfig(query) {
		return this.config.base(query);
	}
	/** 服务端全局配置 */
	globalConfig(query) {
		return this.config.global(query);
	}
	/** 策略配置 */
	strategyConfig(query) {
		return this.config.strategy(query);
	}
	/** 重启降级配置 */
	rebootConfig(query) {
		return this.config.reboot(query);
	}
	/** 用户活跃配置 */
	activeConfig(query) {
		return this.config.active(query);
	}
	/** 用户活跃心跳更新 */
	activeUpdate(query) {
		return this.config.activeUpdate(query);
	}
	/** 上报用户活跃状态 */
	activeStatus(body) {
		return this.config.activeStatus(body);
	}
	/** 进入会话上报 */
	enterChat(body) {
		return this.config.enterChat(body);
	}
	/** 进入消息 Tab 上报 */
	msgTabEnter(body) {
		return this.config.msgTabEnter(body);
	}
	/** 连续聊天关系成就 */
	consecutive(query) {
		return this.growth.consecutive(query);
	}
	/** 成长分享列表 */
	growthShare(body) {
		return this.growth.shareList(body);
	}
	/** 连续聊天开关 */
	consecutiveSwitch(body) {
		return this.growth.switch(body);
	}
	/** 连续聊天上报 */
	consecutiveReport(body) {
		return this.growth.report(body);
	}
	/** 动态策略 */
	growthDynamic(body) {
		return this.growth.dynamic(body);
	}
	/** 语音识别模型配置 */
	audioModel(query) {
		return this.growth.audioModel(query);
	}
	/** 火焰成就 */
	flame(query) {
		return this.growth.flame(query);
	}
	/** Gaga 聚合信息 */
	gaga(body) {
		return this.chatAi.gaga(body);
	}
	/** 宠物聚合信息 */
	pet(body) {
		return this.chatAi.pet(body);
	}
	/** 宠物精灵邀请卡 */
	petCard(query) {
		return this.chatAi.petCard(query);
	}
	/** 子弹事件请求并更新 */
	bullet(body) {
		return this.chatAi.bullet(body);
	}
	/** 子弹事件数据提交 */
	bulletSubmit(body) {
		return this.chatAi.bulletSubmit(body);
	}
	/** 实验命中查询 */
	expHit(body) {
		return this.comm.expHit(body);
	}
	/** 合并消息卡准备 */
	mergePrepare(body) {
		return this.comm.mergePrepare(body);
	}
	/** 通信杂项上报 */
	commMisc(body) {
		return this.comm.misc(body);
	}
	/** 分享上报 */
	shareReport(body) {
		return this.comm.shareReport(body);
	}
	get conv() {
		return this.convBot ??= new Conv(this.agentOf(), this.dev, this.ids);
	}
	get account() {
		return this.accountBot ??= new Account(this.agentOf());
	}
	get notice() {
		return this.noticeBot ??= new Notice(this.agentOf());
	}
	get friend() {
		return this.friendBot ??= new Friend(this.agentOf(), this.dev, this.ids);
	}
	get resource() {
		return this.resourceBot ??= new Resource(this.agentOf());
	}
	get social() {
		return this.socialBot ??= new Social(this.agentOf());
	}
	get group() {
		return this.groupBot ??= new Group(this.agentOf());
	}
	get config() {
		return this.configBot ??= new Config(this.agentOf());
	}
	get growth() {
		return this.growthBot ??= new Growth(this.agentOf());
	}
	get chatAi() {
		return this.chatAiBot ??= new ChatAi(this.agentOf());
	}
	get comm() {
		return this.commBot ??= new Comm(this.agentOf());
	}
	get media() {
		return this.mediaBot ??= new Media(this.agentOf(), this.auth);
	}
	get sender() {
		return this.sendBot ??= new Send(this.conv, this.media, this.comm);
	}
	get recv() {
		if (!this.recvBot) this.recvBot = new Recv({
			dev: this.dev,
			ids: this.ids,
			auth: this.auth,
			log: this.log
		});
		return this.recvBot;
	}
	get login() {
		if (!this.flow) this.flow = new Login({
			auth: this.auth,
			dev: this.dev,
			ids: this.ids
		});
		return this.flow;
	}
	begin(mobile, auth = this.auth) {
		this.flow = new Login({
			auth,
			dev: this.dev,
			ids: this.ids,
			mobile
		});
		this.agent = void 0;
		return this.flow;
	}
	agentOf() {
		if (!this.agent) this.agent = new Im({
			dev: this.dev,
			ids: this.ids,
			auth: this.auth
		});
		return this.agent;
	}
	/**
	* 1105 滑块：回调换 ticket 后重试；没给回调但开了 slide 就起本地验证页并自动续跑。
	* 真机 HAR 实测同一 detail 在 500 后可重新 get 新题再验（native SDK 行为），
	* 因此页面内换题由 slide 自己完成；本层只在决策整体失效时重发登录取新决策。
	*/
	async retry(call, opts, event) {
		let data = await call({});
		if (Number(data.error_code) !== 1105) return data;
		const first = read(this.login.last);
		if (!first) return data;
		this.log.info(`滑块决策 from=${String(first.decision["from"] ?? "")} 字段=${Object.keys(first.decision).length} subtype=${first.subtype}`);
		if (opts.onCaptcha) return call(await opts.onCaptcha(first));
		if (!opts.slide) return data;
		for (let round = 0; round < SLIDE_TRIES; round++) {
			const ch = read(this.login.last);
			if (!ch) return data;
			let page;
			try {
				page = await serve({
					challenge: ch,
					dev: this.dev,
					ids: this.ids,
					auth: this.auth,
					event,
					...typeof opts.slide === "object" ? opts.slide : {}
				});
			} catch (e) {
				this.log.warn(`本地验证页启动失败：${String(e)}`);
				return data;
			}
			if (await page.wait()) return call({ verifyTicket: ch.verifyTicket });
			const why = page.result();
			if (why === "timeout" || why === "closed") return data;
			if (why === "cool") {
				this.log.warn("verify 5014（环境判定），需换网络后重试");
				return data;
			}
			data = await call({});
			if (Number(data.error_code) !== 1105) return data;
		}
		return data;
	}
	/** 2046 二次验证：按优先级尝试，全部完成后重放原请求 */
	async finish(first, opts) {
		let data = first;
		for (let round = 0; round < 3 && Number(data.error_code) === 2046; round++) {
			if (!opts.onMfa && !opts.onQr && !opts.password) return this.res(data);
			if (!await this.verifyOnce(data, opts)) return this.res(data);
			data = await this.login.replayLogin();
		}
		if (Number(data.error_code ?? 0) !== 0) return this.res(data);
		const info = await this.after(data);
		return {
			...this.res(info),
			ok: Boolean(this.auth.sessionid)
		};
	}
	/** 处理一轮验证；返回 false 表示没有可用方式/用户取消 */
	async verifyOnce(data, opts) {
		const ways = data.verify_ways ?? [];
		const way = await this.wayOf(ways, opts);
		if (!way) return false;
		const name = String(way.verify_way ?? "");
		const act = String(way.act_type ?? "22");
		if (name.includes("up_sms")) {
			await opts.onMfa?.({
				way: name,
				kind: "up-sms",
				sms: {
					content: String(way.sms_content ?? ""),
					mobile: way.channel_mobile
				}
			});
			for (let i = 0; i < UP_TRIES; i++) {
				const d = await this.login.upSmsVerify();
				if (d.registered === true || Number(d.error_code) === 0) return true;
				await sleep$1(UP_POLL);
			}
			return false;
		}
		if (name.includes("qr_code")) {
			if (!opts.onQr) return false;
			const q = await this.login.mfaQrGetCode();
			const token = String(q.token ?? "");
			if (!token) return false;
			const index = String(q.qrcode_index_url ?? "");
			const raw = String(q.qrcode ?? "");
			const url = index || (raw.startsWith("http") ? raw : "");
			const base64 = raw && !raw.startsWith("http") ? raw : void 0;
			await opts.onQr({
				url,
				base64
			});
			let last = "";
			for (let i = 0; i < 60; i++) {
				await sleep$1(QR_POLL);
				const d = await this.login.mfaQrCheck(token);
				const st = String(d.status ?? "");
				const ec = Number(d.error_code ?? 0);
				if (`${st}|${ec}` !== last) {
					last = `${st}|${ec}`;
					await opts.onStatus?.(st, ec);
				}
				if (st === "confirmed" || st === "scanned") return true;
				if (st === "expired" || st === "canceled") return false;
			}
			return false;
		}
		if (name.includes("pwd")) {
			const pwd = opts.password ?? (opts.onMfa ? await opts.onMfa({
				way: name,
				kind: "password"
			}) : void 0);
			if (!pwd) return false;
			await this.login.accountVerify(pwd);
			return true;
		}
		if (name && !name.includes("sms")) {
			this.log.warn(`该二次验证方式需在抖音 App 内完成：${name}`);
			return false;
		}
		const mobile = String(way.channel_mobile ?? way.mobile ?? "").replace(/^\+?86/, "").replace(/\D/g, "");
		for (let tries = 0; tries < 3; tries++) {
			await this.login.mfaSendCode(act, mobile);
			const code = opts.onMfa ? await opts.onMfa({
				way: name,
				kind: "sms",
				mobile: String(way.mobile ?? mobile)
			}) : void 0;
			if (!code) {
				this.log.info("未输入验证码，重新发送");
				continue;
			}
			await this.login.validateCode(code, act);
			return true;
		}
		return false;
	}
	/** 选验证方式：交给调用方交互选择，缺省按内置优先级兜底 */
	async wayOf(ways, opts) {
		if (!ways.length) return void 0;
		if (!opts.onWay) return pick(ways);
		const chosen = await opts.onWay(ways);
		if (typeof chosen === "number") return ways[chosen];
		return ways.find((w) => String(w.verify_way ?? "") === chosen) ?? pick(ways);
	}
	/** 登录收尾：update_token → 保存登录信息 → 账号信息 */
	async after(data) {
		const f = this.login;
		try {
			await f.updateToken();
		} catch (e) {
			this.log.warn(`update_token 失败：${String(e)}`);
		}
		try {
			await f.record(2);
		} catch (e) {
			this.log.warn(`保存登录信息失败：${String(e)}`);
		}
		try {
			const info = await f.accountInfo();
			return {
				...data,
				...info
			};
		} catch (e) {
			this.log.warn(`account/info 失败：${String(e)}`);
			return data;
		}
	}
	res(data) {
		const uid = String(data.user_id_str ?? data.user_id ?? data.uid ?? this.auth.jar.get("uid") ?? "");
		const ways = data.verify_ways ?? [];
		return {
			ok: false,
			userId: uid,
			cookie: this.auth.cookie(),
			ids: this.ids,
			data,
			ways: ways.length ? ways : void 0
		};
	}
};
/** 优先级：安全手机 → 绑定手机短信 → 上行短信 → 密码 → 扫码 */
function pick(ways) {
	for (const w of ways) if (String(w.verify_way ?? "").startsWith("assist_") && String(w.verify_way).includes("sms")) return w;
	for (const w of ways) if (String(w.verify_way ?? "").includes("mobile_sms_verify")) return w;
	for (const w of ways) if (String(w.verify_way ?? "").includes("up_sms")) return w;
	for (const w of ways) if (String(w.verify_way ?? "").includes("pwd")) return w;
	return ways[0];
}
function sleep$1(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
//#endregion
//#region src/bot/bot.ts
/** SDK 门面：统一 `bot.域.动作`。收消息走 Android Frontier WS，发消息统一 HTTP cookie 通道 */
var Bot = class extends Emitter {
	msg = new Msg(this);
	media = new Media$1(this);
	frd = new Frd(this);
	grp = new Grp(this);
	chat = new Chat(this);
	user = new User(this);
	sticker = new Sticker(this);
	social = new Social$1(this);
	watch = new Watch(this);
	notice = new Notice$1(this);
	setting = new Setting(this);
	app;
	opts;
	log;
	nicks = new Nicks();
	userId = "";
	core;
	receiver;
	constructor(opts) {
		super();
		this.opts = opts;
		this.log = opts.log ?? createLog({ tag: "bot" });
		this.app = new App({
			cookie: opts.cookie,
			log: this.log,
			...opts.app
		});
	}
	/** 自身数字 uid（start 后可用） */
	get id() {
		return this.userId;
	}
	/** 当前设备身份（start 后可用）；持久化后下次构造用 opts.device 注入，避免重复注册 */
	get device() {
		const http = this.core?.http;
		if (!http || !http.hasDevice()) return void 0;
		return {
			deviceId: http.deviceId,
			installId: http.installId,
			guid: http.guid
		};
	}
	async start() {
		if (this.receiver) return;
		const http = new Http({
			cookie: this.opts.cookie,
			userId: this.opts.userId,
			userAgent: this.opts.userAgent ?? mac.ua,
			timeout: this.opts.timeout,
			log: this.log
		});
		let userId = this.opts.userId ?? "";
		if (!userId) {
			const info = await self(http);
			if (!info.uid) return err(info);
			userId = info.uid;
			if (info.nickname) this.nicks.set(userId, info.nickname);
		}
		if (this.opts.device) http.setDevice(this.opts.device);
		else if (!http.hasDevice()) http.setDevice(await createDevice(this.log));
		const options = {
			http,
			userId,
			cookies: this.opts.cookie,
			deviceId: http.deviceId,
			selfMessage: this.opts.selfMessage,
			log: this.log
		};
		this.core = createCtx(options);
		this.receiver = new Receiver(options);
		this.userId = userId;
		this.wire(this.receiver);
		getFriendList(this.core.inbox).then((list) => this.nicks.remember(list)).catch(() => void 0);
		await this.receiver.start();
	}
	stop() {
		this.receiver?.stop();
	}
	/** 域方法内部取用；未启动即抛出 */
	ctx() {
		if (!this.core) return err({ started: false });
		return this.core;
	}
	http() {
		return this.ctx().http;
	}
	rememberNicks(entries) {
		this.nicks.remember(entries);
	}
	/** 按 uid 查昵称：TTL 内命中直接返回；未命中拉一次好友列表整体回填（发送 @ 自动补昵称用） */
	async nickOf(uid) {
		const cached = this.nicks.get(uid);
		if (cached !== void 0) return cached;
		this.nicks.remember(await getFriendList(this.ctx().inbox).catch(() => []));
		return this.nicks.get(uid);
	}
	/** 发送者昵称补拉：同 uid 并发去重；失败静默不影响下发 */
	ensureNick(msg) {
		if (msg.senderUid === this.userId || this.nicks.has(msg.senderUid)) return Promise.resolve();
		return this.nicks.once(msg.senderUid, () => this.fetchNick(msg));
	}
	async fetchNick(msg) {
		if (msg.conversationType === 2) {
			const members = await getGroupMembers(this.ctx().inbox, toAddress(chatIdOf(msg)));
			this.nicks.remember(members);
			const profiles = await getUserProfiles(this.ctx().http, members.map((m) => m.secUid ?? ""));
			for (const m of members) {
				const nickname = m.secUid ? profiles.get(m.secUid)?.nickname : void 0;
				if (nickname) this.nicks.set(m.uid, nickname);
			}
			return;
		}
		if (msg.senderSecUid) {
			const nickname = (await getUserProfiles(this.ctx().http, [msg.senderSecUid])).get(msg.senderSecUid)?.nickname;
			if (nickname) this.nicks.set(msg.senderUid, nickname);
			return;
		}
		const [friends, strangers] = await Promise.all([getFriendList(this.ctx().inbox), getStrangerList(this.ctx().inbox)]);
		this.nicks.remember([...friends, ...strangers]);
	}
	/** 把接收层推送接到 Bot 事件层：message 类补 chatId 与昵称，其余原样透传 */
	wire(receiver) {
		receiver.on("message", (msg) => void this.forward("message", msg));
		receiver.on("message:edited", (msg) => void this.forward("message:edited", msg));
		receiver.on("notice", (event) => this.emit("notice", event));
		receiver.on("request", (event) => this.emit("request", event));
		receiver.on("voip", (event) => this.emit("voip", event));
		receiver.on("read", (event) => this.emit("read", event));
		receiver.on("status", (event) => this.emit("status", event));
		receiver.on("reconnecting", (event) => this.emit("reconnecting", event));
		receiver.on("close", (event) => this.emit("close", event));
	}
	/** 等昵称与视频地址补拉完成再下发，首条消息即带完整字段 */
	async forward(event, msg) {
		await Promise.all([this.ensureNick(msg), this.ensureVideoUrl(msg)]);
		this.emit(event, {
			...msg,
			chatId: chatIdOf(msg),
			senderNickname: this.nicks.get(msg.senderUid)
		});
	}
	/** 视频播放地址补拉：随事件直接下发，失败静默（调用方仍可 media.videoUrl 手动换） */
	async ensureVideoUrl(msg) {
		if (msg.type !== "video" || !("url" in msg.video)) return;
		try {
			msg.video.url = await getVideoUrl(this.ctx().http, msg.video.tkey);
		} catch {}
	}
};
//#endregion
//#region src/session/res.ts
/**
* Passport 二级验证决策头。与客户端一致：头存在就要先完成安全验证再重放原请求。
*/
function verifyDecision(headers) {
	return headers.get(hdr.verify) || void 0;
}
//#endregion
//#region src/session/verify/json.ts
/** JSON 与字段编码:所有非结构化响应都先按 unknown 收窄,避免 any 泄漏 */
function asRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value) ? value : void 0;
}
function asStringRecord(value) {
	const record = asRecord(value);
	if (!record) return {};
	return Object.fromEntries(Object.entries(record).filter(([, item]) => item != null).map(([key, item]) => [key, String(item)]));
}
function tryParse(value) {
	try {
		return JSON.parse(value);
	} catch {
		return value;
	}
}
/** 嵌入页面的 JSON 必须转义 <>&,否则字符串里的 <\/script> 会截断脚本块 */
function safeJson(value) {
	return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
function escapeHtml(value) {
	return value.replace(/[&<>"']/g, (char) => ({
		"&": "&amp;",
		"<": "&lt;",
		">": "&gt;",
		"\"": "&quot;",
		"'": "&#39;"
	})[char]);
}
/** Passport 字段编码:字符串原样,数字/布尔转字符串,对象 JSON 序列化 */
function encodeField(value) {
	if (typeof value === "string") return value;
	if (typeof value === "number" || typeof value === "boolean") return String(value);
	return JSON.stringify(value);
}
/** 验证结果字段回填 check_qrconnect body 时统一转为字符串 */
function stringifyFields(fields) {
	return Object.fromEntries(Object.entries(fields).filter(([, value]) => value != null).map(([key, value]) => [key, encodeField(value)]));
}
//#endregion
//#region src/session/verify/decision.ts
/** 决策解析:按官方客户端优先级挑选验证中心下发的配置 */
/**
* 响应头决策优先于响应体:真实客户端把该头原样交给 SecondVerify SDK,
* 头存在即代表必须二次验证,body 里的 conf 只是补充。
*/
function parseDecision(data, header) {
	if (typeof header === "string" && header.length > 0) {
		const record = asRecord(tryParse(header));
		if (record) return {
			raw: JSON.stringify(record),
			decision: {
				...record,
				verification_level: vc.level
			},
			secondary: true
		};
		return {
			raw: header,
			decision: {
				verify_data: header,
				verification_level: vc.level
			},
			secondary: true
		};
	}
	const source = data;
	const nested = asRecord(source["data"]);
	const selected = [
		[nested?.["verify_center_decision_conf"], false],
		[nested?.["verify_center_secondary_decision_conf"], true],
		[source["verify_center_decision_conf"], false],
		[source["verify_center_secondary_decision_conf"], true]
	].find(([value]) => Boolean(value));
	const rawValue = selected?.[0];
	const secondary = selected?.[1] === true;
	const record = asRecord(rawValue);
	if (record) return {
		raw: JSON.stringify(record),
		decision: {
			...record,
			...secondary ? { verification_level: vc.level } : {}
		},
		secondary
	};
	if (typeof rawValue === "string" && rawValue.length > 0) return {
		raw: rawValue,
		decision: {
			...parseConf(rawValue),
			...secondary ? { verification_level: vc.level } : {}
		},
		secondary
	};
}
/** conf 既可能是对象 JSON,也可能直接是字符串,统一包成 verify_data */
function parseConf(value) {
	const parsed = tryParse(value);
	return asRecord(parsed) ?? { verify_data: parsed };
}
//#endregion
//#region src/session/verify/sdk.ts
/** 本地静态资源:React 运行时与官方 SecondVerify SDK */
/** 资源随包发布,运行期只读盘一次 */
function asset(file) {
	return readFile(join(assetDir(file), file));
}
function loadReact() {
	return Promise.all([asset("react.production.min.js"), asset("react-dom.production.min.js")]);
}
/** 决策未带 url 时用本地内置官方 SDK;缓存避免每轮验证重复读盘 */
let cached;
function loadSdk() {
	cached ??= asset("second-verification-web.js");
	return cached;
}
//#endregion
//#region src/session/lite.ts
/** desktop lite Passport 传输层（imdesktop 域 + jumpbyte a_bogus），扫码 MFA 与安全验证共用 */
/** 未注册设备时 lite 接口的进程内随机 DID 兜底 */
const fallbackDid = randomHex(16);
/** 字段顺序对齐 jumpbyte canonical，服务端按原序验签 */
function liteQuery(deviceId) {
	return {
		passport_jssdk_version: lite.jssdk,
		passport_jssdk_type: lite.type,
		is_from_ttaccountsdk: lite.fromSdk,
		aid: passport.aid,
		language: lite.lang,
		account_app_language: lite.appLang,
		is_new_login: lite.newLogin,
		is_from_iesaccountsaas: lite.fromSaas,
		biz_trace_id: randomHex(8),
		new_authn_sdk_version: lite.authn,
		device_id: deviceId,
		iid: lite.iid,
		version_code: im.version,
		device_platform: lite.platform
	};
}
async function form(http, path, body) {
	const query = {
		...liteQuery(http.hasDevice() ? http.deviceId : fallbackDid),
		msToken: randomMsToken()
	};
	const bodyWire = encodeDesktopParams(body);
	const queryWire = encodeDesktopParams(query);
	const bogus = aBogusDesktop({
		userAgent: http.ua,
		query: queryWire,
		body: bodyWire
	});
	const url = `${passport.origin}${path}?${queryWire}&a_bogus=${encodeURIComponent(bogus)}`;
	const res = await http.json(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Referer: `${im.origin}/`
		},
		body: bodyWire
	});
	if (!res.ok) return err(res.data);
	return res.data;
}
//#endregion
//#region src/session/verify/proxy.ts
/** 验证组件请求代理:登录域带 Cookie,验证中心域不带,防止登录态串到 zijieapi */
/** 验证页代理允许访问的主机 */
const ALLOWED = /* @__PURE__ */ new Set([
	host.im,
	host.login,
	host.verify,
	host.vcs,
	host.web
]);
/** 带账号 Cookie + Passport 头的登录域;验证中心域(zijieapi)不带 Cookie,避免混入登录态 */
const AUTH = /* @__PURE__ */ new Set([
	host.im,
	host.login,
	host.web
]);
/** 服务端 5001/2040/2046 常伴随参数错误,输出轨迹才能定位是哪个 SDK 字段不对 */
const TRACE = /:5001|=5001|"5001"|\[5001\]|error_code["']?\s*[:=]\s*20(46|40)/;
/** 页面可透传的头必须剔除跳转/凭据/长度类字段,否则浏览器与 Node 会自行改写或报错 */
const BLOCKED = /* @__PURE__ */ new Set([
	"connection",
	"content-length",
	"cookie",
	"host",
	"origin",
	"proxy-authorization",
	"referer",
	"set-cookie",
	"transfer-encoding"
]);
function allowHost(url) {
	if (ALLOWED.has(url.hostname.toLowerCase())) return;
	err({ host: url.hostname });
}
function cleanHeaders(headers) {
	return Object.fromEntries(Object.entries(headers).filter(([key]) => !BLOCKED.has(key.toLowerCase())));
}
async function requestRaw(http, url, init) {
	const hostname = new URL(url).hostname.toLowerCase();
	if (AUTH.has(hostname)) {
		const res = await http.request(url, {
			...init,
			headers: {
				...http.passportHeaders(url),
				...init.headers
			}
		});
		trace(http, url, init, res.status, res.text);
		return {
			ok: res.ok,
			status: res.status,
			headers: res.headers,
			text: res.text
		};
	}
	const res = await fetch(url, {
		...init,
		headers: {
			"User-Agent": http.ua,
			...init.headers
		},
		signal: AbortSignal.timeout(time.fetch)
	});
	const text = await res.text();
	trace(http, url, init, res.status, text);
	return {
		ok: res.ok,
		status: res.status,
		headers: res.headers,
		text
	};
}
function trace(http, url, init, status, body) {
	const text = body.slice(0, 300);
	if (status >= 200 && status < 300 && !TRACE.test(text)) return;
	http.log.warn(`verify ${String(init.method ?? "GET")} ${url} -> ${status} ${text}`);
}
//#endregion
//#region src/session/verify/center.ts
/** 验证中心配置换取:把决策换成动态脚本地址与 captcha 业务参数 */
/**
* verify_center 决策只带业务意图,组件脚本与 scene_level 要从 vcs 拉取;
* is_login 由服务端自行推导,回传会被判定参数错误。
*/
async function packWays(http, decision, deviceId, aid) {
	const body = {};
	const requestData = {
		aid,
		...decision,
		device_id: deviceId,
		iid: fld.iid,
		version_code: im.version,
		device_platform: mac.platform
	};
	for (const [key, value] of Object.entries(requestData)) {
		if (key === "is_login" || value == null) continue;
		body[key] = encodeField(value);
	}
	const res = await form(http, path.pack, body);
	if (res.data.error_code != null && res.data.error_code !== 0) err(res);
	return res.data;
}
/** 配置拉取失败不阻断:内置官方 SDK 地址仍可完成验证 */
async function loadSetting(http, deviceId, aid) {
	try {
		const query = new URLSearchParams({
			aid: String(aid),
			did: deviceId || fld.iid,
			iid: fld.iid
		});
		const res = await requestRaw(http, `${vc.setting}?${query}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Setting-Flag": vc.flag
			},
			body: "{}"
		});
		if (!res.ok) return void 0;
		const parsed = asRecord(tryParse(res.text));
		return asRecord((asRecord(parsed?.["data"]) ?? parsed)?.["verify"]);
	} catch {
		return;
	}
}
/** 配置里的脚本地址按优先级拼接,内置地址永远兜底 */
function scriptsOf(setting) {
	const primary = asRecord(setting?.["js_v2"])?.["cn"];
	const backups = asRecord(setting?.["back_up_js_v2"])?.["cn"];
	const urls = [
		...typeof primary === "string" ? [primary] : [],
		...Array.isArray(backups) ? backups.filter((value) => typeof value === "string") : [],
		vc.center,
		...vc.centerBackups
	];
	return [...new Set(urls)];
}
/** 官方成功链路 captcha/get 必带这些参数,缺失返回 501 */
function captchaOptions(config) {
	const scene = config["scene_level"] == null || config["scene_level"] === "" ? vc.scene : String(config["scene_level"]);
	return {
		scene,
		options: {
			repoId: vc.repo,
			h5_check_version: vc.h5,
			extraConfig: vc.extra,
			scene_level: scene
		}
	};
}
//#endregion
//#region src/session/verify/prepare.ts
/** 验证组件准备:平台判定与两种组件形态的配置组装 */
/**
* 网页登录与桌面 IM 的验证服务 host 不同,SDK 用 host 拼相对路径;
* 用表驱动而不是 if,新增客户端场景只加一行。
*/
const PLATFORM = [{
	aid: vc.webAid,
	host: `https://${host.web}`,
	appName: "抖音 Web 站"
}, {
	aid: Number(im.aid),
	host: `https://${host.im}`,
	appName: "抖音聊天"
}];
async function prepare(http, descriptor, hooks) {
	const decisionAid = Number(asRecord(descriptor.decision)?.["aid"] ?? 0);
	const aid = hooks.aid ?? (decisionAid > 0 ? decisionAid : Number(im.aid));
	const platform = PLATFORM.find((item) => item.aid === aid) ?? PLATFORM[1];
	const deviceId = deviceOf(http);
	let config = { ...descriptor.decision };
	const verifyFrom = String(config["verify_from"] ?? "");
	const byCode = vc.codes.includes(Number(config["code"]));
	if (!byCode && verifyFrom === vc.from) config = {
		...config,
		...await packWays(http, config, deviceId, aid)
	};
	const base = {
		config,
		fp: `${vc.fpPrefix}${deviceId}`,
		deviceId,
		aid,
		host: hooks.host ?? platform.host,
		appName: platform.appName
	};
	if (byCode) {
		const setting = await loadSetting(http, deviceId, aid);
		const scene = captchaOptions(config);
		return {
			...base,
			config: {
				...config,
				scene_level: scene.scene
			},
			mode: "verify-center",
			scripts: scriptsOf(setting),
			options: scene.options
		};
	}
	const rawUrl = typeof config["url"] === "string" ? config["url"] : void 0;
	if (!rawUrl) return {
		...base,
		mode: "second-verify"
	};
	const script = new URL(rawUrl);
	if (script.protocol !== "https:") err({ protocol: script.protocol });
	script.searchParams.set("aid", String(aid));
	const event = asRecord(config["event_params"]);
	script.searchParams.set("verify_reason", String(event?.["verify_reason"] ?? ""));
	script.searchParams.set("verify_scene", String(event?.["verify_scene"] ?? ""));
	return {
		...base,
		mode: "second-verify",
		script: script.toString()
	};
}
/** 对齐 douyin-im:验证组件复用连接上已注册的设备身份,无注册设备才回退随机 hex */
function deviceOf(http) {
	return http.hasDevice() ? http.deviceId : randomHex(16);
}
//#endregion
//#region src/session/verify/bridge.ts
/** 页面与官方验证组件之间的桥接脚本:请求代理、环境注入、启动验证 */
function bridge(appVersion) {
	return String.raw`
    (() => {
      const boot = window.__LOGIN_VERIFY__;
      localStorage.setItem('${vc.webId}', boot.fp);
      document.cookie = '${vc.webId}=' + encodeURIComponent(boot.fp) + '; path=/';
      // 页面侧轨迹必须走未经包装的原始 fetch 并对同内容去重,否则上报动作本身会再触发 fetch 包装,形成日志风暴。
      const rawFetch = window.fetch.bind(window);
      const pageLogCache = {};
      const pageLog = (line) => {
        try {
          const key = String(line).slice(0, 200);
          const now = Date.now();
          if (pageLogCache[key] && now - pageLogCache[key] < 800) return;
          pageLogCache[key] = now;
          rawFetch('/api/log?token=' + encodeURIComponent(boot.sessionToken), {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({line})});
        } catch (e) {}
      };
      window.addEventListener('error', (e) => pageLog('window.error: ' + (e.message || '') + ' @' + (e.filename || '') + ':' + (e.lineno || '')), true);
      window.addEventListener('unhandledrejection', (e) => pageLog('unhandledrejection: ' + ((e.reason && (e.reason.message || e.reason)) || String(e.reason))));
      const origFetch = window.fetch;
      window.fetch = (...args) => {
        const target = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
        const method = ((args[1] && args[1].method) || 'GET');
        const isLog = String(target).includes('/api/log');
        if (!isLog) pageLog('fetch ' + method + ' ' + target);
        return origFetch.apply(window, args).then((res) => {
          if (!res.ok && !isLog) pageLog('fetch ERR ' + method + ' ' + target + ' -> ' + res.status);
          return res;
        }).catch((e) => { if (!isLog) pageLog('fetch FAIL ' + method + ' ' + target + ' ' + (e.message || e)); throw e; });
      };
      // 官方验证码 SDK 走原生 XHR(非 fetch):同样截获轨迹(vc/setting、滑块提交等)
      const xhrOpen = XMLHttpRequest.prototype.open;
      const xhrSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        this.__pxMethod = String(method || 'GET');
        this.__pxUrl = String(url || '');
        pageLog('xhr ' + this.__pxMethod + ' ' + this.__pxUrl);
        return xhrOpen.apply(this, [method, url, ...rest]);
      };
      XMLHttpRequest.prototype.send = function (...rest) {
        const self = this;
        this.addEventListener('loadend', () => {
          if (!self.__pxUrl) return;
          const text = String(self.responseText || '').slice(0, 160).replace(/\s+/g, ' ');
          pageLog('xhr END ' + self.__pxMethod + ' ' + self.__pxUrl + ' -> ' + self.status + ' ' + text);
        });
        return xhrSend.apply(this, rest);
      };
      const complete = async (result = {}) => {
        const response = await fetch('/api/complete?token=' + encodeURIComponent(boot.sessionToken), {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({result})});
        const data = await response.json();
        if (!response.ok || data.error) throw new Error(data.error || '恢复登录失败');
        document.getElementById('app').innerHTML = '<main class="card"><h1>验证通过</h1><p>正在继续登录,可以关闭此页。</p></main>';
      };
      const proxy = async (config = {}) => {
        const encode = (value) => value instanceof Date ? value.toISOString() : value && typeof value === 'object' ? JSON.stringify(value) : String(value);
        const params = new URLSearchParams();
        Object.entries(config.params || {}).forEach(([key, value]) => {
          if (value == null) return;
          if (Array.isArray(value)) value.forEach(item => params.append(key + '[]', encode(item)));
          else params.append(key, encode(value));
        });
        let url = config.url || '';
        if (params.size) url += (url.includes('?') ? '&' : '?') + params;
        let body = config.data;
        const headers = {...(config.headers || {})};
        const contentTypeKey = Object.keys(headers).find(key => key.toLowerCase() === 'content-type');
        const contentType = contentTypeKey ? String(headers[contentTypeKey]).toLowerCase() : '';
        if (body instanceof FormData) {
          const form = new URLSearchParams();
          for (const [key, value] of body.entries()) form.append(key, encode(value));
          body = form.toString();
          headers[contentTypeKey || 'Content-Type'] = 'application/x-www-form-urlencoded';
        } else if (body && typeof body === 'object') {
          if (contentType.includes('application/json')) body = JSON.stringify(body);
          else {
            const form = new URLSearchParams();
            Object.entries(body).forEach(([key, value]) => {
              if (value == null) return;
              if (Array.isArray(value)) value.forEach(item => form.append(key + '[]', encode(item)));
              else form.append(key, encode(value));
            });
            body = form.toString();
            headers[contentTypeKey || 'Content-Type'] = 'application/x-www-form-urlencoded';
          }
        }
        const response = await fetch('/api/request?token=' + encodeURIComponent(boot.sessionToken), {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url,baseURL:config.baseURL,method:config.method || 'GET',headers,body})});
        const result = await response.json();
        if (!response.ok || result.error) throw result;
        const axiosResponse = {data: result.data, status: result.status, statusText: result.statusText, headers: result.headers, config};
        if (result.status < 200 || result.status >= 300) {
          const error = new Error('Request failed with status code ' + result.status);
          error.response = axiosResponse;
          error.config = config;
          throw error;
        }
        return axiosResponse;
      };
      window.$$UCALL_APIMAP = window.$$UCALL_APIMAP || {};
      window.$$UCALL_APIMAP['Request.fetch'] = proxy;
      window.$$UCALL_APIMAP['Request.fetchSec'] = proxy;
      window.$$UCALL_APIMAP.Request = proxy;
      window.$$UC_CORE_ENV = {env:'online',container:'web',region:'CN'};
      window.$$UC_ENV_PROMISE = Promise.resolve(window.$$UC_CORE_ENV);
      window.$$UCALL_APIMAP.getEnv = () => window.$$UC_ENV_PROMISE;
      window.$$UCALL_APIMAP.getQuery = () => Object.fromEntries(new URLSearchParams(location.search));
      window.$$UCALL_APIMAP.getSettings = (params) => proxy({url:'/service/settings/v3/',params});
      window.ucSecondVerifyReact = window.React;
      window.ucSecondVerifyReactDom = window.ReactDOM;
      const loadScript = (urls) => new Promise((resolve, reject) => {
        const remaining = [...urls];
        const next = () => {
          const url = remaining.shift();
          if (!url) return reject(new Error('抖音验证 SDK 加载失败'));
          const script = document.createElement('script');
          script.crossOrigin = 'anonymous';
          script.src = url;
          script.onload = resolve;
          script.onerror = next;
          document.head.appendChild(script);
        };
        next();
      });
      // hook iframe.src:外层 XHR 看不到 iframe 内的 /captcha/get,但 iframe URL 能确认 repoId/h5_check_version 是否透传
      const frameDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
      if (frameDesc && frameDesc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
          get () { return frameDesc.get.call(this); },
          set (v) {
            try {
              const s = String(v);
              if (s.includes('rmc.bytedance.com') || s.includes('verifycenter')) {
                pageLog('iframe src ' + s.slice(0, 700));
              }
            } catch (e) {}
            return frameDesc.set.call(this, v);
          },
          configurable: true,
        });
      }
      window.startDouyinVerification = async () => {
        // 官方 captcha/get 不带 did(随机 hex did 会被判参数错误 501),故 commonOptions 不再传 did
        const common = {aid:boot.aid,iid:String(boot.config.iid || '0'),...(boot.config.scene_level ? {scene_level:boot.config.scene_level} : {})};
        if (boot.mode === 'verify-center') {
          await loadScript(boot.captchaScriptUrls || []);
          const sdk = window.verifySDK;
          if (!sdk) throw new Error('抖音验证码 SDK 加载失败');
          const captchaOptions = {fp:boot.fp,app_name:boot.appName,lang:'zh',showMode:'mask',region:'cn',baseEM:70,...(boot.captchaOptions || {})};
          const origInit = sdk.initVerifyOptions.bind(sdk);
          sdk.initVerifyOptions = (opt) => { pageLog('initVerifyOptions ' + JSON.stringify(opt).slice(0, 600)); return origInit(opt); };
          sdk.initVerifyOptions({commonOptions:common,captchaOptions});
          const success = () => {
            // getCaptchaWebId 可能返回对象;服务端 fp 只接受 verify_* 字符串,非法值会污染下一次登录请求
            const webId = sdk.getCaptchaWebId && sdk.getCaptchaWebId();
            const fp = typeof webId === 'string' && webId.startsWith('${vc.fpPrefix}') ? webId : boot.fp;
            complete({fp});
          };
          const close = () => fetch('/api/cancel?token=' + encodeURIComponent(boot.sessionToken),{method:'POST'});
          // 决策 JSON 里的 did 会被 SDK 透传进 iframe URL → captcha/get 501,故先删
          const verifyData = {...boot.config};
          delete verifyData.did;
          sdk.autoRender({verify_data:verifyData,captchaOptions:{successCb:success,closeCb:close,errorCb:()=>{}},secondVerifyWebOptions:{callBack:success,closeCallBack:close}});
          return;
        }
        await loadScript(boot.scriptUrl ? [boot.scriptUrl] : ['/second-verify-sdk.js?token=' + encodeURIComponent(boot.sessionToken)]);
        if (typeof window.ucWebSecondVerify !== 'function') throw new Error('抖音二次验证 SDK 加载失败');
        const callback = () => complete({});
        const generalParams = {is_new_login:'1',is_from_iesaccountsaas:1};
        const getGeneralParams = async () => ({device_id:boot.deviceId,iid:common.iid,version_code:${JSON.stringify(appVersion)},device_platform:${JSON.stringify(mac.platform)}});
        const monitorTime = {startTime:Date.now(),fetchEndTime:Date.now(),scriptLoadStartTime:0,scriptLoadEndTime:Date.now(),renderStartTime:Date.now()};
        window.$$account_verify_portrait_id = boot.config.verify_portrait_id || '';
        const verifyData = {...boot.config};
        delete verifyData.did;
        window.ucWebSecondVerify({...verifyData,aid:boot.aid,appName:boot.appName,did:boot.deviceId,iid:common.iid,host:boot.host,newSecondVerifyRequestHost:boot.host,newSecondVerificationCall:{reportAppLog:()=>{}},region:'cn',hcSwitch:false,isOversea:false,ztsdk:false,ztsdkOptions:{agid:1,enableCookieOptions:false},ssoZtsdkOptions:{enable:false},captchaOptions:{fp:boot.fp,baseEM:70},commonOptions:common,generalParams,getGeneralParams,monitorTime,uc_account_verify_version:'${vc.sdk}',fun:boot.config.verify_from === '${vc.from}' ? '${vc.from}' : 'verify',Request:proxy,request:proxy,verifyFinishCallback:callback,callBack:callback,closeCallBack:()=>fetch('/api/cancel?token=' + encodeURIComponent(boot.sessionToken),{method:'POST'})});
      };
    })();
  `;
}
//#endregion
//#region src/session/verify/page.ts
/** 验证页 HTML:注入启动数据与桥接脚本,React 由本地静态路由提供 */
function page(prep, token) {
	const boot = {
		mode: prep.mode,
		config: prep.config,
		fp: prep.fp,
		sessionToken: token,
		deviceId: prep.deviceId,
		aid: prep.aid,
		host: prep.host,
		appName: prep.appName
	};
	if (prep.mode === "verify-center") {
		boot["captchaScriptUrls"] = prep.scripts;
		boot["captchaOptions"] = prep.options;
	} else if (prep.script) boot["scriptUrl"] = prep.script;
	const quoted = encodeURIComponent(token);
	return shell("抖音登录安全验证", `
    <div id="app"><div class="loading">正在加载抖音安全验证…</div></div>
    <script src="/react.js?token=${quoted}"><\/script>
    <script src="/react-dom.js?token=${quoted}"><\/script>
    <script>window.__LOGIN_VERIFY__=${safeJson(boot)};<\/script>
    <script>${bridge(im.version)}<\/script>
    <script>window.startDouyinVerification();<\/script>
  `);
}
function shell(title, body) {
	return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:#f5f5f5;color:#161823;font-family:system-ui,-apple-system,sans-serif;display:grid;place-items:center}.card{width:min(420px,calc(100vw - 32px));background:white;border-radius:16px;padding:28px;box-shadow:0 12px 48px #0001}.card h1{font-size:22px;margin:0 0 12px}.card p,.loading{color:#666}#app{min-width:min(420px,calc(100vw - 32px))}
  </style></head><body>${body}</body></html>`;
}
//#endregion
//#region src/session/verify/route.ts
/** 页面侧只允许这些方法,避免被拿来做任意协议探测 */
const METHODS = /* @__PURE__ */ new Set([
	"GET",
	"POST",
	"PUT",
	"PATCH",
	"DELETE",
	"HEAD",
	"OPTIONS"
]);
/** 页面轨迹按内容节流:曾出现 /api/log 自激循环导致终端卡顿 */
const THROTTLE = 600;
const MAXLINES = 2e3;
const logs = /* @__PURE__ */ new Map();
const pages = { "/": (state) => page(state.prep, state.token) };
const scripts = {
	"/react.js": (state) => state.react,
	"/react-dom.js": (state) => state.reactDom,
	"/second-verify-sdk.js": () => loadSdk()
};
const apis = {
	"/api/request": async (request, response, state) => {
		const payload = await readJsonBody(request);
		const target = resolveUrl(payload["url"], payload["baseURL"] ?? state.prep.host);
		allowHost(target);
		const method = String(payload["method"] ?? "GET").toUpperCase();
		if (!METHODS.has(method)) err({ method });
		const body = typeof payload["body"] === "string" ? payload["body"] : void 0;
		const result = await requestRaw(state.http, target.toString(), {
			method,
			headers: cleanHeaders(asStringRecord(payload["headers"])),
			...body !== void 0 && method !== "GET" && method !== "HEAD" ? { body } : {}
		});
		sendJson(response, 200, {
			data: tryParse(result.text),
			rawText: result.text,
			status: result.status,
			statusText: result.ok ? "OK" : "ERROR",
			headers: Object.fromEntries([...result.headers.entries()].filter(([key]) => key.toLowerCase() !== "set-cookie"))
		});
	},
	"/api/complete": async (request, response, state) => {
		const result = asRecord((await readJsonBody(request))["result"]);
		const fields = asRecord(result?.["fields"] ?? result) ?? {};
		const fp = String(result?.["fp"] ?? "") || state.prep.fp;
		sendJson(response, 200, { ok: true });
		state.finish(void 0, {
			fp,
			fields
		});
	},
	"/api/log": async (request, response, state) => {
		const payload = await readJsonBody(request);
		const line = String(payload["line"] ?? "").slice(0, 500);
		const now = Date.now();
		const last = logs.get(line);
		if (last === void 0 || now - last > THROTTLE) {
			logs.set(line, now);
			if (logs.size > MAXLINES) logs.clear();
			state.http.log.info(`verify:page ${line}`);
		}
		sendJson(response, 200, { ok: true });
	},
	"/api/cancel": async (_request, response, state) => {
		sendJson(response, 200, { ok: true });
		state.finish(new SdkError({ cancel: true }));
	}
};
async function route(request, response, state) {
	const url = new URL(request.url ?? "/", "http://127.0.0.1");
	if (url.searchParams.get("token") !== state.token) {
		sendJson(response, 403, { error: "登录验证会话无效" });
		return;
	}
	if (request.method === "GET") {
		const html = pages[url.pathname];
		if (html) {
			sendHtml(response, html(state));
			return;
		}
		const script = scripts[url.pathname];
		if (script) {
			sendScript(response, await script(state));
			return;
		}
	}
	if (request.method === "POST") {
		const api = apis[url.pathname];
		if (api) {
			await api(request, response, state);
			return;
		}
	}
	response.writeHead(404);
	response.end("Not Found");
}
function resolveUrl(urlValue, baseValue) {
	return new URL(String(urlValue ?? ""), String(baseValue ?? im.origin));
}
async function readJsonBody(request) {
	const chunks = [];
	let length = 0;
	for await (const chunk of request) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		length += buffer.length;
		if (length > 1048576) err({ length });
		chunks.push(buffer);
	}
	const text = Buffer.concat(chunks).toString("utf8") || "{}";
	return JSON.parse(text);
}
function sendJson(response, status, data) {
	response.writeHead(status, {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store"
	});
	response.end(JSON.stringify(data));
}
function sendHtml(response, html) {
	response.writeHead(200, {
		"content-type": "text/html; charset=utf-8",
		"cache-control": "no-store",
		"referrer-policy": "no-referrer"
	});
	response.end(html);
}
function sendScript(response, script) {
	response.writeHead(200, {
		"content-type": "text/javascript; charset=utf-8",
		"cache-control": "public, max-age=3600"
	});
	response.end(script);
}
//#endregion
//#region src/session/verify/server.ts
/** 启动本地验证页并等待用户完成官方安全验证 */
async function verify(http, descriptor, hooks = {}) {
	const timeoutMs = hooks.timeoutMs ?? time.verify;
	const [react, reactDom] = await loadReact();
	const prep = await prepare(http, descriptor, hooks);
	return new Promise((resolve, reject) => {
		let finished = false;
		const token = randomUUID();
		const finish = (error, outcome) => {
			if (finished) return;
			finished = true;
			clearTimeout(timer);
			server.close(() => error ? reject(error) : resolve(outcome ?? { fields: {} }));
		};
		const server = createServer((request, response) => {
			route(request, response, {
				http,
				prep,
				react,
				reactDom,
				token,
				finish
			}).catch((error) => {
				sendJson(response, 500, { error: error instanceof Error ? error.message : String(error) });
			});
		});
		server.once("error", (error) => finish(error));
		const timer = setTimeout(() => finish(new SdkError({ timeout: timeoutMs })), timeoutMs);
		timer.unref();
		server.listen(0, "0.0.0.0", () => {
			const address = server.address();
			if (typeof address !== "object" || address === null) {
				finish(new SdkError({ address }));
				return;
			}
			const url = `http://127.0.0.1:${address.port}/?token=${encodeURIComponent(token)}`;
			http.log.info(`登录安全验证页: ${url}`);
			hooks.onUrl?.(url);
		});
	});
}
//#endregion
//#region src/session/login/verify.ts
/** 验证中心决策:风控/滑块等非 0 error_code 下发的本地安全验证 */
/** 有决策则拉起本地验证页并把结果字段交回轮询;无决策返回 undefined */
async function verifyCenter(http, data, decision, opts) {
	const center = parseDecision(data, decision);
	if (!center) return;
	const outcome = await verify(http, center, {
		onUrl: opts.onVerifyUrl,
		aid: Number(passport.aid)
	});
	return {
		fields: stringifyFields(outcome.fields),
		fp: outcome.fp
	};
}
//#endregion
//#region src/session/sign/mix.ts
/**
* Passport `mix_mode=1`：明文 UTF-8 逐字节 XOR 0x05，两位小写 hex 拼接。
*/
function mixEncode(plain) {
	const bytes = Buffer.from(plain, "utf8");
	let out = "";
	for (let i = 0; i < bytes.length; i++) out += (bytes[i] ^ 5).toString(16).padStart(2, "0");
	return out;
}
//#endregion
//#region src/session/login/mfa.ts
/** 短信 / 上行短信 / 密码二次验证:方式选择、发码、校验与上行短信轮询 */
function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
/** 验证方式优先级:安全手机短信 > 绑定手机短信 > 上行短信(用安全手机发短信)> 登录密码 */
function selectWay(data) {
	const ways = data.verify_ways ?? [];
	return way.order.map((name) => ways.find((w) => w.verify_way === name)).find(Boolean);
}
/** 验证方式分发:方式与流程解耦,新增方式只加一行 */
const flows = {
	[way.upSms]: (flow) => upSms(flow.http, flow.challenge, flow.selected, flow.opts.onStatus),
	[way.password]: (flow) => password(flow.http, flow.challenge, flow.opts),
	[way.assistSms]: sms,
	[way.sms]: sms
};
/** 短信/密码二次验证:按优先级选择方式,通过后返回轮询需携带的 biz 参数 */
async function mfa(http, data, opts) {
	const challenge = {
		encrypt_uid: data.encrypt_uid,
		biz_params: data.biz_params,
		common_params: data.common_params
	};
	const ways = data.verify_ways ?? [];
	const chosen = await opts.onVerifyWays?.(ways);
	const selected = chosen == null ? selectWay(data) : ways.find((w) => w.verify_way === chosen);
	if (!selected?.verify_way) {
		if (chosen != null) err({
			chosen,
			verify_ways: ways
		});
		err({ verify_ways: ways });
	}
	const name = selected.verify_way;
	await (flows[name] ?? sms)({
		http,
		data,
		challenge,
		selected,
		name,
		opts
	});
	return pickBiz(data.biz_params);
}
/** 短信验证码流程:依次尝试发码(选中的方式 → 辅助手机兜底),被拒时回退上行短信 */
async function sms(flow) {
	const { http, data, challenge, selected, name, opts } = flow;
	if (!opts.onMfa) err({ onMfa: false });
	const candidates = name === way.sms ? [way.sms, way.assistSms] : [name];
	let sent;
	let used;
	for (const candidate of candidates) {
		const res = await sendCode(http, challenge, candidate);
		sent = res;
		if (res.message === fld.smsOk) {
			used = candidate;
			break;
		}
	}
	if (sent?.message !== fld.smsOk || used === void 0) {
		const falling = (data.verify_ways ?? []).find((w) => w.verify_way === way.upSms);
		if (falling?.verify_way) {
			await opts.onStatus?.(`发码被拒(${sent?.message ?? "unknown"}${sent?.data.description ? `: ${sent.data.description}` : ""}),改用上行短信验证`);
			await upSms(http, challenge, falling, opts.onStatus);
			return;
		}
		err(sent);
	}
	if (used !== name) await opts.onStatus?.(msg.assistSwitch);
	const maskedMobile = sent.data.mobile ?? selected.mobile;
	const code = await opts.onMfa({
		kind: "sms",
		maskedMobile: maskedMobile != null ? String(maskedMobile) : void 0
	});
	const validated = await validateCode(http, challenge, used, code);
	if (!validated.data.ticket) err(validated);
	await opts.onStatus?.(st.verified);
}
/** 登录密码验证:无需发码,直接提交密码 */
async function password(http, challenge, opts) {
	if (!opts.onMfa) err({ onMfa: false });
	const input = await opts.onMfa({ kind: "password" });
	if (!input) err({ password: input });
	const validated = await validatePassword(http, challenge, input);
	if (!validated.data.ticket) err(validated);
	await opts.onStatus?.(msg.pwdOk);
}
/** 上行短信验证:用安全手机编辑指定短信发送到服务端号码,轮询 validate_code 等确认 */
async function upSms(http, challenge, selected, onStatus) {
	const content = selected.sms_content || fld.defaultSms;
	await onStatus?.(`请用安全手机(${selected.mobile ?? ""})编辑短信"${content}"发送到 ${selected.channel_mobile ?? ""}`);
	const deadline = Date.now() + time.upTimeout;
	while (Date.now() < deadline) {
		await sleep(time.upPoll);
		let res;
		try {
			res = await validateCode(http, challenge, selected.verify_way ?? way.upSms);
		} catch {
			continue;
		}
		if (res.data.ticket) {
			await onStatus?.(msg.smsOk);
			return;
		}
	}
	err({ timeout: time.upTimeout });
}
function sendCode(http, challenge, verifyWay) {
	return form(http, path.send, mfaBody(challenge, verifyWay, { is6Digits: fld.sixDigits }));
}
function validateCode(http, challenge, verifyWay, code) {
	const encoded = code == null ? void 0 : verifyWay === way.sms ? mixEncode(code) : xorHex(code);
	return form(http, path.validate, mfaBody(challenge, verifyWay, encoded != null ? { code: encoded } : {}));
}
/**
* 登录密码二次验证(pwd_verify,逆向自 second-verification-web.js):
* POST /passport/web/account/verify/,password 字段 xorHex(Xor5+hex)编码 + mix_mode=1,
* 无 type/send_code 步骤,成功返回 data.ticket。
*/
function validatePassword(http, challenge, passwordText) {
	return form(http, path.password, mfaBody(challenge, way.password, { password: xorHex(passwordText) }));
}
/** code_encrypt:UTF-8 每字节 ^5 后的两位 hex(363c 场景配套) */
function xorHex(s) {
	const hex = "0123456789abcdef";
	let out = "";
	for (const ch of s) {
		const c = ch.codePointAt(0) ?? 0;
		const bytes = c <= 127 ? [c] : c <= 2047 ? [192 | c >> 6 & 31, 128 | c & 63] : c <= 65535 ? [
			224 | c >> 12 & 15,
			128 | c >> 6 & 63,
			128 | c & 63
		] : [];
		for (const b of bytes) out += hex[(b ^ 5) >> 4] + hex[(b ^ 5) & 15];
	}
	return out;
}
//#endregion
//#region src/session/login/session.ts
/** Session 组装:uid 兜底与真实资料覆盖 */
function sessionOf(http, userData) {
	const userId = userData?.user_id_str ?? (userData?.user_id != null ? String(userData.user_id) : void 0) ?? http.jar.get(ck.uid);
	if (!userId) err({ userId });
	const session = {
		userId,
		cookie: http.jar.header()
	};
	if (userData) session.userData = userData;
	return session;
}
/** passport 的昵称/头像多为占位值,用真实资料覆盖(失败不阻断) */
async function finalize(http, session) {
	await self(http).then((profile) => {
		session.userData = {
			...session.userData,
			...profile.nickname ? { screen_name: profile.nickname } : {},
			...profile.avatar ? { avatar_url: profile.avatar } : {}
		};
	}).catch(() => void 0);
	return session;
}
//#endregion
//#region src/session/login/poll.ts
/** 二维码取码与 check_qrconnect 轮询主循环 */
/** 默认 SDK 内部日志:登录链路失败原因需可见,静默轮询会让卡点无从定位 */
const log = createLog({ tag });
/** message 恒为 sdk,日志必须补 data 才能定位 */
const why = (error) => isErr(error) ? JSON.stringify(error.data) : error instanceof Error ? error.message : String(error);
/**
* 轮询间隔按已完成的外层轮数递增:官方客户端在 60/180 轮后把间隔提到 3s/5s,
* 固定 1s 长时间轮询会让服务端把整段登录判成频繁访问(error_code=7)
*/
const pace = (count) => count >= 180 ? time.pollMax : count >= 60 ? time.pollMid : time.poll;
/** 去掉每轮都重算的参数,留下可原样重放的签名 query */
function strip(query) {
	const copy = { ...query };
	delete copy.msToken;
	delete copy.a_bogus;
	return copy;
}
/** GET /passport/web/get_qrcode/,返回二维码 token 与 base64 图片 */
async function getQr(http) {
	const { search } = signQuery(passportBaseQuery({
		deviceId: http.deviceId,
		installId: http.installId,
		accountSdkSourceInfo: sdkSourceInfo(http),
		bizTraceId: http.bizTraceId,
		next: qr.next,
		extra: {
			need_logo: qr.needLogo,
			need_short_url: qr.needShort
		}
	}), {}, signExtras(http));
	const url = `${passport.origin}${path.qrcode}?${search}`;
	const res = await http.json(url, { headers: http.passportHeaders(url) });
	const d = res.data.data;
	if (d.error_code !== 0) err(res.data);
	return {
		token: d.token,
		base64: d.qrcode,
		indexUrl: d.qrcode_index_url
	};
}
/**
* POST /passport/web/check_qrconnect/;postSign 为验证字段,在签名之后追加进 body
* (HAR 实证:确认轮 sign 只覆盖基础 body,std_verify_* 不参与签名);
* resume 为验证完成后的重放签名,官方只补 fp 与验证字段而不重算 sign/qs
*/
async function checkQr(http, token, postSign, fp, resume) {
	const body = qrBody(token);
	const bodyWire = postSign ? encodeForm({
		...body,
		...postSign
	}) : encodeForm(body);
	const extras = signExtras(http, bodyWire);
	const signed = resume ? resumeQuery(fp ? {
		...resume,
		fp
	} : resume, extras) : signQuery(passportBaseQuery({
		deviceId: http.deviceId,
		installId: http.installId,
		accountSdkSourceInfo: sdkSourceInfo(http),
		bizTraceId: http.bizTraceId,
		...fp ? { extra: { fp } } : {}
	}), body, extras);
	const url = `${passport.origin}${path.check}?${signed.search}`;
	const res = await http.json(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			...http.passportHeaders(url)
		},
		body: bodyWire
	});
	return {
		data: res.data.data,
		message: res.data.message,
		decision: verifyDecision(res.headers),
		signed: strip(signed.query)
	};
}
/** 轮询直至 confirmed / expired / 超时 */
async function poll(http, token, opts) {
	let deadline = Date.now() + time.timeout;
	let last;
	let notified;
	let extra = {};
	let fp;
	let signed;
	let replay = false;
	let count = 0;
	let verifyCount = 0;
	let mfaDone = false;
	let frequent = 0;
	let transient = 0;
	let missing = 0;
	const retry = (code) => {
		if ((code === 6 || code === "ECONNABORTED") && transient < 3) {
			transient += 1;
			return true;
		}
		if (!code && missing < 3) {
			missing += 1;
			return true;
		}
		return false;
	};
	while (Date.now() < deadline) {
		if (!replay) count += 1;
		let res;
		try {
			res = await checkQr(http, token, extra, fp, replay ? signed : void 0);
		} catch (e) {
			if (!retry(isErr(e) ? e.data?.error_code : void 0)) throw e;
			log.warn(`check_qrconnect 异常: ${why(e)}`);
			await sleep(pace(count));
			replay = false;
			continue;
		}
		last = res.data;
		signed = res.signed;
		const code = Number(last.error_code ?? 0);
		const ok = res.message === "success";
		if (!ok) log.warn(`check_qrconnect error_code=${code} ${String(last.description ?? "")}`);
		if (!ok && verifyCount < ec.verifyLimit) {
			const center = await verifyCenter(http, last, res.decision, opts);
			if (center) {
				verifyCount += 1;
				await opts.onStatus?.(st.verifying);
				extra = {
					...extra,
					...center.fields
				};
				fp = center.fp ?? fp;
				await opts.onStatus?.(st.verified);
				deadline = Date.now() + time.timeout;
				replay = true;
				continue;
			}
		}
		if (!ok && !mfaDone && (last.account_flow === fld.accountFlow || last.biz_params != null)) {
			await opts.onStatus?.(st.verifying);
			try {
				extra = {
					...extra,
					...await mfa(http, last, opts)
				};
				mfaDone = true;
				deadline = Date.now() + time.timeout;
			} catch (e) {
				log.warn(`二次验证不可自动完成: ${why(e)}`);
				await opts.onStatus?.(msg.appVerify);
				await sleep(time.appVerifyWait);
				replay = false;
				continue;
			}
			replay = true;
			continue;
		}
		replay = false;
		if (!ok) {
			if (code === ec.tooFrequent) {
				if (frequent >= ec.frequentLimit) err(last);
				frequent += 1;
				const wait = time.pollMax * frequent;
				log.warn(`check_qrconnect 触发频控,${wait}ms 后重试 ${frequent}/${ec.frequentLimit}`);
				deadline += wait;
				await sleep(wait);
				continue;
			}
			if (code === ec.appVerify) {
				if (notified !== "app_verify") {
					notified = "app_verify";
					await opts.onStatus?.(msg.appVerify);
				}
				await sleep(time.appVerifyWait);
				continue;
			}
			err(last);
		}
		if (last.status && last.status !== notified) {
			notified = last.status;
			await opts.onStatus?.(last.status);
		}
		if (last.status === st.confirmed) return sessionOf(http, last.user_data);
		if (last.status === st.expired) err(last);
		await sleep(pace(count));
	}
	err({
		timeout: time.timeout,
		status: last?.status
	});
}
//#endregion
//#region src/session/login/warm.ts
/** imdesktop 域 ttwid 预热:官方客户端冷启动向同域 ttwid 服务领取 ttwid,缺失时确认轮触发 2156/2046 */
async function warm(http) {
	await http.request(`${im.origin}${path.ttwid}`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			aid: Number(passport.aid),
			service: fld.service
		})
	});
}
//#endregion
//#region src/session/login/login.ts
/** 扫码登录对外入口:设备注册 → 取码 → 轮询 → 安全验证 / MFA → 会话。不落盘任何东西。 */
/** 扫码登录全流程;调用链形态对齐 douyin-im beginLogin 桌面流程 */
async function login(opts = {}) {
	const http = new Http({
		userAgent: opts.userAgent ?? passport.ua,
		log: opts.log
	});
	const device = opts.device ?? await createDevice(opts.log);
	http.setDevice(device);
	await warm(http).catch(() => void 0);
	const qr = await getQr(http);
	await opts.onQr?.({
		url: qr.indexUrl ?? qr.token,
		base64: qr.base64
	});
	const session = await poll(http, qr.token, opts);
	session.device = device;
	return finalize(http, session);
}
//#endregion
//#region src/media/box.ts
/** 纯容器 box（body 全部为子 box） */
const CONTAINERS = /* @__PURE__ */ new Set([
	"moov",
	"trak",
	"mdia",
	"minf",
	"stbl",
	"sinf",
	"schi"
]);
function fourcc(buf, off) {
	return buf.toString("latin1", off, off + 4);
}
function find(boxes, type) {
	return boxes.find((node) => node.type === type);
}
/** sample entry 固定字段（encv=78/enca=28 等）之后的子 box 起点：滑窗找首个合法 box */
function entryChildStart(buf, body, end) {
	for (let off = body + 8; off + 8 <= end; off++) {
		const size = buf.readUInt32BE(off);
		if (size < 8 || off + size > end) continue;
		if (/^[\x20-\x7e]{4}$/.test(fourcc(buf, off + 4))) return off;
	}
	return end;
}
function parseBoxes(buf, start, end, stsd = false) {
	const list = [];
	let off = start;
	while (off + 8 <= end) {
		let size = buf.readUInt32BE(off);
		let hdr = 8;
		if (size === 1) {
			if (off + 16 > end) break;
			size = Number(buf.readBigUInt64BE(off + 8));
			hdr = 16;
		} else if (size === 0) size = end - off;
		if (size < hdr || off + size > end) break;
		const type = fourcc(buf, off + 4);
		const body = off + hdr;
		const node = {
			type,
			start: off,
			body,
			end: off + size
		};
		if (type === "stsd") node.children = parseBoxes(buf, body + 8, node.end, true);
		else if (stsd || type === "encv" || type === "enca") node.children = parseBoxes(buf, entryChildStart(buf, body, node.end), node.end);
		else if (CONTAINERS.has(type)) node.children = parseBoxes(buf, body, node.end);
		list.push(node);
		off += size;
	}
	return list;
}
//#endregion
//#region src/media/plan.ts
/** 解析 tenc：KID 固定占 box 尾 16 字节（抖音将其设为解密 key），IV_size 在其前 1 字节 */
function parseTenc(tenc, buf) {
	const len = tenc.end - tenc.body;
	return { ivSize: buf[tenc.body + len - 17] };
}
/** senc box → 每样本 IV/子样本序列（抖音样本的辅助数据源；saiz/saio 为同内容的偏移定位变体，仅 senc 缺失时兜底） */
function parseAux(buf, senc, saiz, saio, count, ivSize) {
	const auxs = [];
	if (senc) {
		const withSub = (buf.readUInt32BE(senc.body) & 16777215) !== 0;
		let off = senc.body + 8;
		for (let i = 0; i < count; i++) {
			const iv = Buffer.from(buf.subarray(off, off + ivSize));
			off += ivSize;
			const subsamples = [];
			if (withSub) {
				const n = buf.readUInt16BE(off);
				off += 2;
				for (let k = 0; k < n; k++) {
					subsamples.push({
						clear: buf.readUInt16BE(off),
						protected: buf.readUInt32BE(off + 2)
					});
					off += 6;
				}
			}
			auxs.push({
				iv,
				subsamples
			});
		}
		return auxs;
	}
	if (saiz && saio && ivSize > 0) {
		const flags = buf[saiz.body + 7];
		const def = buf[saiz.body + 12];
		const sizeOf = (k) => flags & 1 ? buf[saiz.body + 17 + k] : def;
		let aux = saio.body + 4;
		if ((buf.readUInt32BE(saio.body) & 1) === 1) aux += 8;
		let at = buf[saio.body] === 1 ? Number(buf.readBigUInt64BE(aux + 4)) : buf.readUInt32BE(aux + 4);
		for (let i = 0; i < count; i++) {
			const iv = Buffer.from(buf.subarray(at, at + ivSize));
			const subsamples = [];
			let pos = at + ivSize;
			if (sizeOf(i) > ivSize) {
				const n = buf.readUInt16BE(pos);
				pos += 2;
				for (let k = 0; k < n; k++) {
					subsamples.push({
						clear: buf.readUInt16BE(pos),
						protected: buf.readUInt32BE(pos + 2)
					});
					pos += 6;
				}
			}
			at += sizeOf(i);
			auxs.push({
				iv,
				subsamples
			});
		}
		return auxs;
	}
	return auxs;
}
/** 从 stbl 组装解密计划：样本定位（stsz/stsc/stco）+ 每样本 IV/子样本（senc 或 saiz/saio 或 constant_iv） */
function planTrack(buf, stbl, entry) {
	const sinf = find(entry.children ?? [], "sinf");
	const frma = find(sinf?.children ?? [], "frma");
	const tenc = find(find(sinf?.children ?? [], "schi")?.children ?? [], "tenc");
	if (!sinf || !frma || !tenc) err({ bytes: buf.length });
	const { ivSize } = parseTenc(tenc, buf);
	if (ivSize !== 8 && ivSize !== 16) err({ ivSize });
	const stsz = find(stbl.children, "stsz");
	const stsc = find(stbl.children, "stsc");
	const stco = find(stbl.children, "stco") ?? find(stbl.children, "co64");
	if (!stsz || !stco || !stsc) err({ bytes: buf.length });
	const b = stsz.body;
	const uniform = buf.readUInt32BE(b + 4);
	const count = buf.readUInt32BE(b + 8);
	const sizes = [];
	for (let i = 0; i < count; i++) sizes.push(uniform > 0 ? uniform : buf.readUInt32BE(b + 12 + i * 4));
	const chunkCounts = [];
	{
		const n = buf.readUInt32BE(stsc.body + 4);
		const chunks = buf.readUInt32BE(stco.body + 4);
		for (let i = 0; i < n; i++) {
			const base = stsc.body + 8 + i * 12;
			const first = buf.readUInt32BE(base);
			const per = buf.readUInt32BE(base + 4);
			const span = (i + 1 < n ? buf.readUInt32BE(stsc.body + 8 + (i + 1) * 12) : chunks + 1) - first;
			for (let j = 0; j < span; j++) chunkCounts.push(per);
		}
	}
	const samples = [];
	{
		let index = 0;
		for (let c = 0; c < chunkCounts.length && index < count; c++) {
			const base = stco.type === "co64" ? stco.body + 8 + c * 8 : stco.body + 8 + c * 4;
			const offset = stco.type === "co64" ? Number(buf.readBigUInt64BE(base)) : buf.readUInt32BE(base);
			let acc = 0;
			for (let j = 0; j < chunkCounts[c] && index < count; j++) {
				samples.push({
					offset: offset + acc,
					size: sizes[index]
				});
				acc += sizes[index];
				index++;
			}
		}
	}
	const auxs = parseAux(buf, find(stbl.children, "senc"), find(stbl.children, "saiz"), find(stbl.children, "saio"), count, ivSize);
	if (auxs.length !== count) err({
		aux: auxs.length,
		count
	});
	return {
		stbl,
		entry,
		rawFourcc: fourcc(buf, frma.body),
		samples,
		auxs
	};
}
//#endregion
//#region src/media/cenc.ts
/** 收集 moov 下所有加密轨的解密计划（只有 encv/enca sample entry 才需要处理） */
function trackPlans(buf, moov) {
	const plans = [];
	for (const trak of moov.children.filter((node) => node.type === "trak")) {
		const stbl = find(find(find(trak.children, "mdia")?.children ?? [], "minf")?.children ?? [], "stbl");
		const entry = (stbl && find(stbl.children, "stsd"))?.children?.[0];
		if (!stbl || !entry || entry.type !== "encv" && entry.type !== "enca") continue;
		plans.push(planTrack(buf, stbl, entry));
	}
	return plans;
}
/** 逐加密轨原位解密 mdat 样本 */
function decryptSamples(buf, plans, key) {
	for (const plan of plans) plan.samples.forEach((sample, i) => {
		const { iv, subsamples } = plan.auxs[i];
		decryptCencSample(buf.subarray(sample.offset, sample.offset + sample.size), key, iv, subsamples).copy(buf, sample.offset);
	});
}
/** 容器子 box 起点：stsd 固定 8 字节扩展，改名后的 sample entry 需滑窗定位 */
function prefixOf(node, ctx) {
	if (node.type === "stsd") return node.body + 8;
	return ctx.renamed.has(node) ? entryChildStart(ctx.buf, node.body, node.end) : node.body;
}
function size(node, ctx) {
	if (ctx.deleted.has(node)) return 0;
	if (!node.children) {
		const total = node.end - node.start;
		ctx.sizes.set(node, total);
		return total;
	}
	let total = prefixOf(node, ctx) - node.start;
	for (const child of node.children) total += size(child, ctx);
	ctx.sizes.set(node, total);
	return total;
}
/** moov 在 mdat 之前时删除保护 box 会使 mdat 绝对偏移前移，需修正 stco/co64 */
function shift(ctx, moov, mdat, plans) {
	const shrink = moov.end - moov.start - (ctx.sizes.get(moov) ?? 0);
	if (moov.end > mdat.start || shrink <= 0) return;
	for (const plan of plans) {
		const stco = find(plan.stbl.children, "stco") ?? find(plan.stbl.children, "co64");
		if (!stco) continue;
		const n = ctx.buf.readUInt32BE(stco.body + 4);
		for (let i = 0; i < n; i++) if (stco.type === "co64") {
			const at = stco.body + 8 + i * 8;
			ctx.buf.writeBigUInt64BE(ctx.buf.readBigUInt64BE(at) + BigInt(shrink), at);
		} else {
			const at = stco.body + 8 + i * 4;
			ctx.buf.writeUInt32BE(ctx.buf.readUInt32BE(at) + shrink, at);
		}
	}
}
function emit(node, ctx, out, pos) {
	if (ctx.deleted.has(node)) return pos;
	out.writeUInt32BE(ctx.sizes.get(node), pos);
	out.write(ctx.renamed.get(node) ?? node.type, pos + 4, "latin1");
	pos += 8;
	if (!node.children) {
		ctx.buf.copy(out, pos, node.body, node.end);
		return pos + node.end - node.body;
	}
	const prefixEnd = prefixOf(node, ctx);
	ctx.buf.copy(out, pos, node.body, prefixEnd);
	pos += prefixEnd - node.body;
	for (const child of node.children) pos = emit(child, ctx, out, pos);
	return pos;
}
/** 重建输出：sample entry 改回原始 fourcc，删除保护结构（sinf/senc/saiz/saio/sgpd/sbgp 的 seig 项） */
function rebuild(buf, top, plans, moov, mdat) {
	const ctx = {
		buf,
		deleted: /* @__PURE__ */ new Set(),
		renamed: /* @__PURE__ */ new Map(),
		sizes: /* @__PURE__ */ new Map()
	};
	for (const plan of plans) {
		ctx.renamed.set(plan.entry, plan.rawFourcc);
		const sinf = find(plan.entry.children ?? [], "sinf");
		if (sinf) ctx.deleted.add(sinf);
		for (const node of plan.stbl.children) {
			if (node.type === "senc" || node.type === "saiz" || node.type === "saio") ctx.deleted.add(node);
			if ((node.type === "sgpd" || node.type === "sbgp") && fourcc(buf, node.body + 4) === "seig") ctx.deleted.add(node);
		}
	}
	for (const node of top) size(node, ctx);
	shift(ctx, moov, mdat, plans);
	const out = Buffer.alloc(top.reduce((sum, node) => sum + (ctx.sizes.get(node) ?? 0), 0));
	let pos = 0;
	for (const node of top) pos = emit(node, ctx, out, pos);
	return out;
}
/**
* 解密 CENC(cenc 方案) 加密 mp4：keyHex 为消息 `video.skey`（32 hex = 16 字节 AES-128）。
* 输出可直接播放的 mp4；未加密的输入原样返回。
*/
function decryptCencMp4(data, keyHex) {
	const key = Buffer.from(keyHex, "hex");
	if (key.length !== 16) err({ length: keyHex.length });
	const buf = Buffer.from(data);
	const top = parseBoxes(buf, 0, buf.length);
	const moov = find(top, "moov");
	const mdat = find(top, "mdat");
	if (!moov) err({ bytes: buf.length });
	if (!mdat) err({ bytes: buf.length });
	const plans = trackPlans(buf, moov);
	if (plans.length === 0) return buf;
	decryptSamples(buf, plans, key);
	return rebuild(buf, top, plans, moov, mdat);
}
//#endregion
export { App, Bot, SdkError, chatIdOf, createLog, decryptCencMp4, isErr, login };
