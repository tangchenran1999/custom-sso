import { withPluginApi } from "discourse/lib/plugin-api";

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded, path:", window.location.pathname);

      // ── 关键修复：如果当前 URL 是 /custom-sso/* 后端路由，
      //    说明 Discourse 的 Ember SPA 错误地拦截了本应由 Rails 处理的请求。
      //    这种情况下 Ember 会尝试用 AJAX 请求该 URL，导致 403。
      //    解决方案：检测到这种情况后，强制用完整页面导航重新请求。
      const path = window.location.pathname;
      if (
        path.startsWith("/custom-sso/login") ||
        path.startsWith("/custom-sso/callback") ||
        path.startsWith("/custom-sso/complete-profile") ||
        path.startsWith("/custom-sso/create-account")
      ) {
        // eslint-disable-next-line no-console
        console.log("[custom-sso] backend route detected, forcing full page navigation");
        // 使用 document.location.href 赋值触发完整页面加载
        // 加一个 _t 参数防止缓存，同时作为标记防止无限循环
        if (!window.location.search.includes("_sso_reload=1")) {
          const sep = window.location.search ? "&" : "?";
          window.location.href =
            window.location.href + sep + "_sso_reload=1";
          return;
        }
        // 如果已经有 _sso_reload=1 还是到了这里，说明路由确实没注册成功
        // 不做任何事，让 Ember 显示 404 页面
        return;
      }

      // ── 全局保护：拦截所有可能错误提交到 /custom-sso/login 的请求 ────────
      // Discourse 使用 AJAX 提交登录表单，所以需要拦截 fetch 和 XMLHttpRequest
      (function() {
        // 保存原始的 fetch
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
          const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
          const method = args[1]?.method || args[0]?.method || 'GET';
          
          // 如果请求 URL 包含 /custom-sso/login，且不是 GET 请求，阻止它
          if (url && url.includes('/custom-sso/login')) {
            if (method.toUpperCase() !== 'GET') {
              // eslint-disable-next-line no-console
              console.error("[custom-sso] 阻止了错误的 fetch", method, "请求到 /custom-sso/login，URL:", url);
              return Promise.reject(new Error("不允许非 GET 请求到 /custom-sso/login"));
            }
          }
          
          return originalFetch.apply(this, args);
        };

        // 拦截 XMLHttpRequest（Discourse 可能使用）
        const originalXHROpen = XMLHttpRequest.prototype.open;
        const originalXHRSend = XMLHttpRequest.prototype.send;
        
        // 重写 open 方法以保存 method 和 url，并检查
        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
          this._method = method;
          this._url = url;
          
          // 如果请求 URL 包含 /custom-sso/login，且不是 GET 请求，阻止它
          if (typeof url === 'string' && url.includes('/custom-sso/login') && method.toUpperCase() !== 'GET') {
            // eslint-disable-next-line no-console
            console.error("[custom-sso] 阻止了错误的 XHR", method, "请求到 /custom-sso/login，URL:", url);
            throw new Error("不允许非 GET 请求到 /custom-sso/login");
          }
          
          return originalXHROpen.apply(this, [method, url, ...rest]);
        };
        
        // 拦截 XMLHttpRequest 的 send 方法（额外保护）
        XMLHttpRequest.prototype.send = function(...args) {
          const url = this._url || '';
          if (url && url.includes('/custom-sso/login') && this._method && this._method.toUpperCase() !== 'GET') {
            // eslint-disable-next-line no-console
            console.error("[custom-sso] 阻止了错误的 XHR send", this._method, "请求到 /custom-sso/login");
            throw new Error("不允许非 GET 请求到 /custom-sso/login");
          }
          return originalXHRSend.apply(this, args);
        };
      })();

      function insertSsoButton() {
        // 已经有就不重复插
        if (document.querySelector(".custom-sso-btn")) {
          return;
        }

        // 尝试找到登录按钮容器
        const container =
          document.querySelector(".login-buttons") ||
          document.querySelector(".auth-buttons");

        if (!container) {
          return;
        }

        // 注意：不再主动查找和修改登录表单，避免干扰 Discourse 的正常处理
        // 只通过拦截 fetch/XHR 来保护，不直接操作表单

        const btn = document.createElement("button");
        btn.className = "btn btn-primary custom-sso-btn";
        btn.type = "button"; // 关键：type="button" 确保不会触发表单提交
        btn.textContent = "统一身份认证";
        // 添加明确的标识，避免与原生登录按钮混淆
        btn.setAttribute("data-custom-sso", "true");
        btn.style.marginBottom = "10px"; // 添加间距，与原生按钮区分

        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();

          // eslint-disable-next-line no-console
          console.log("[custom-sso] 用户点击了统一身份认证按钮，跳转到 SSO 登录");
          
          // 跳转到 /custom-sso/login，后端会直接构造 OAuth authorize URL
          // 跳转到认证中心。如果用户未登录，认证中心会展示登录页面；
          // 登录成功后认证中心带 code 回调到 /custom-sso/callback，
          // 全程不经过门户 portal 页面。
          const loginPath = window.location.origin + "/custom-sso/login";
          // eslint-disable-next-line no-console
          console.log("[custom-sso] navigating to", loginPath);
          window.location.replace(loginPath);
        });

        // 放到最前面
        container.prepend(btn);

        // 注意：不再直接监听表单提交，避免干扰 Discourse 的正常处理和 CSRF token 传递
        // 保护措施已通过拦截 fetch/XHR 实现，这已经足够防止错误的请求到达后端

        // eslint-disable-next-line no-console
        console.log("[custom-sso] button inserted - 注意：此按钮仅用于统一身份认证，不影响原生登录/注册功能");
      }

      // SPA 路由切到 /login 时，尝试插一次
      api.onPageChange((url) => {
        if (url && url.indexOf("/login") !== -1) {
          setTimeout(insertSsoButton, 0);
        }
      });

      // 初次加载就尝试一次（直接访问 /login 的情况）
      insertSsoButton();

      // 监听 DOM 变化（登录弹窗 / 切 tab / 异步渲染等）
      const observer = new MutationObserver(() => {
        insertSsoButton();
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true,
      });
    });
  },
};
