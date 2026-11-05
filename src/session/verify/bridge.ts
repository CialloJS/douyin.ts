/** 页面与官方验证组件之间的桥接脚本:请求代理、环境注入、启动验证 */
import { mac } from '../sign/const.js'
import { vc } from '../login/codes.js'

export function bridge (appVersion: string): string {
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
  `
}
