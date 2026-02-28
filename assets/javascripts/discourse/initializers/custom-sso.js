import { withPluginApi } from "discourse/lib/plugin-api";

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded");

      // ── 防止原生登录成功后回跳到 /custom-sso/login ─────────
      // 有些情况下（例如之前访问过 /custom-sso/login），Discourse 会把它保存成登录后的 redirect/return_path。
      // 用户选择"原生登录"时，这会导致登录成功后又被带回 /custom-sso/login。
      // 这里在 /login 页面把这种 redirect 参数改写成 "/"，避免回跳。
      function sanitizeLoginRedirectParams() {
        try {
          const u = new URL(window.location.href);
          const keys = ["redirect", "return_path", "destination_url", "return_to"];
          let changed = false;

          keys.forEach((k) => {
            const v = u.searchParams.get(k);
            if (v && (v.includes("/custom-sso/login") || v === "/custom-sso/login")) {
              u.searchParams.set(k, "/");
              changed = true;
              // eslint-disable-next-line no-console
              console.warn(`[custom-sso] sanitized ${k} parameter from ${v} to /`);
            }
          });

          if (changed) {
            const next =
              u.pathname +
              (u.searchParams.toString() ? `?${u.searchParams.toString()}` : "") +
              u.hash;
            window.history.replaceState({}, document.title, next);
            // eslint-disable-next-line no-console
            console.warn("[custom-sso] detected bad login redirect to /custom-sso/login; rewrote to /");
          }
        } catch (e) {
          // eslint-disable-next-line no-console
          console.warn("[custom-sso] failed to sanitize login redirect params", e);
        }
      }

      // 在 /login 页面立即执行
      if (window.location.pathname === "/login") {
        sanitizeLoginRedirectParams();
      }

      // 监听 URL 变化（SPA 路由切换）
      let lastUrl = window.location.href;
      setInterval(() => {
        if (window.location.href !== lastUrl) {
          lastUrl = window.location.href;
          if (window.location.pathname === "/login") {
            sanitizeLoginRedirectParams();
          }
        }
      }, 100);

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
        if (!window.location.search.includes("_sso_reload=1")) {
          const sep = window.location.search ? "&" : "?";
          window.location.href = window.location.href + sep + "_sso_reload=1";
          return;
        }
        return;
      }

      // ── 监听登录成功事件，防止跳转到 /custom-sso/login ────────
      // Discourse 登录成功后可能会跳转到之前访问过的 URL
      // 如果这个 URL 是 /custom-sso/login，我们需要拦截并重定向到首页
      function interceptLoginSuccessRedirect() {
        // 监听所有导航事件
        const originalPushState = history.pushState;
        const originalReplaceState = history.replaceState;
        
        function checkAndFixUrl(url) {
          if (typeof url === 'string' && url.includes('/custom-sso/login')) {
            // eslint-disable-next-line no-console
            console.warn("[custom-sso] intercepted redirect to /custom-sso/login, redirecting to / instead");
            return url.replace(/\/custom-sso\/login[^?]*/, '/').replace(/\/custom-sso\/login/, '/');
          }
          return url;
        }
        
        history.pushState = function(...args) {
          if (args[2]) {
            args[2] = checkAndFixUrl(args[2]);
          }
          return originalPushState.apply(this, args);
        };
        
        history.replaceState = function(...args) {
          if (args[2]) {
            args[2] = checkAndFixUrl(args[2]);
          }
          return originalReplaceState.apply(this, args);
        };
        
        // 监听 popstate 事件（浏览器前进/后退）
        window.addEventListener('popstate', () => {
          if (window.location.pathname === '/custom-sso/login') {
            // eslint-disable-next-line no-console
            console.warn("[custom-sso] detected navigation to /custom-sso/login via popstate, redirecting to /");
            window.location.replace('/');
          }
        });
        
        // 定期检查当前 URL（作为最后一道防线）
        setInterval(() => {
          if (window.location.pathname === '/custom-sso/login' && document.cookie.includes('_t=')) {
            // 如果已经登录但还在 /custom-sso/login 页面，重定向到首页
            // eslint-disable-next-line no-console
            console.warn("[custom-sso] user is logged in but on /custom-sso/login page, redirecting to /");
            window.location.replace('/');
          }
        }, 500);
      }
      
      interceptLoginSuccessRedirect();

      // ── 关键保护：确保原生登录表单不会被误拦截 ────────
      // 1. 主动修复登录表单的 action（如果被错误修改）
      function fixLoginFormAction() {
        // 查找所有可能的登录表单
        const loginForms = document.querySelectorAll(
          'form[action*="/session"], form.login-form, form#login-form, form[data-login-form]'
        );
        
        loginForms.forEach((form) => {
          const action = form.getAttribute("action") || "";
          // 如果表单的 action 被错误地改成了 /custom-sso/login，修复它
          if (action.includes("/custom-sso/login")) {
            // eslint-disable-next-line no-console
            console.warn("[custom-sso] 检测到登录表单 action 被错误修改，正在修复...");
            // 恢复为正确的 Discourse 登录端点
            form.setAttribute("action", "/session");
            // eslint-disable-next-line no-console
            console.log("[custom-sso] 已修复登录表单 action 为 /session");
          }
        });
      }
      
      // 2. 监听表单提交，进行最后的安全检查
      document.addEventListener("submit", function(e) {
        const form = e.target;
        if (!form || form.tagName !== "FORM") {
          return;
        }
        
        const action = form.getAttribute("action") || "";
        const method = (form.getAttribute("method") || "GET").toUpperCase();
        
        // 如果是原生登录表单提交到 /session，确保不被拦截
        if (action.includes("/session") && method === "POST") {
          // eslint-disable-next-line no-console
          console.log("[custom-sso] 检测到原生登录表单提交，确保不被拦截");
          // 不做任何处理，让原生登录正常进行
          return;
        }
        
        // 如果表单被错误地提交到 /custom-sso/login，阻止它并修复
        if (action.includes("/custom-sso/login") && method === "POST") {
          // eslint-disable-next-line no-console
          console.error("[custom-sso] 阻止了错误的表单提交到 /custom-sso/login");
          e.preventDefault();
          e.stopPropagation();
          
          // 尝试修复表单 action
          if (form.querySelector('input[name="username"], input[name="login"]')) {
            // 这看起来是登录表单，修复它的 action
            form.setAttribute("action", "/session");
            // eslint-disable-next-line no-console
            console.log("[custom-sso] 已修复表单 action，请重新提交");
          }
          
          return false;
        }
      }, true); // 使用捕获阶段，确保优先处理
      
      // 3. 定期检查并修复登录表单（防止被其他代码修改）
      setInterval(fixLoginFormAction, 1000);
      
      // 4. 在 DOM 变化时也检查并修复
      const formObserver = new MutationObserver(() => {
        fixLoginFormAction();
      });
      
      formObserver.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["action"]
      });

      // ── 只插入 SSO 按钮，不修改任何其他元素，不影响原生登录 ────────
      function insertSsoButton() {
        // 如果已经插入了，就不再插入
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

        // 创建 SSO 按钮
        const btn = document.createElement("button");
        btn.className = "btn btn-primary custom-sso-btn";
        btn.type = "button"; // 关键：type="button" 确保不会触发表单提交
        btn.textContent = "统一身份认证";
        btn.setAttribute("data-custom-sso", "true"); // 明确标识这是 SSO 按钮
        btn.style.marginBottom = "10px";

        // 只监听 SSO 按钮的点击事件
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();

          // eslint-disable-next-line no-console
          console.log("[custom-sso] 用户点击了统一身份认证按钮");
          
          // 跳转到 SSO 登录
          const loginPath = window.location.origin + "/custom-sso/login";
          window.location.replace(loginPath);
        });

        // 插入到容器最前面
        container.prepend(btn);

        // eslint-disable-next-line no-console
        console.log("[custom-sso] SSO 按钮已插入 - 不影响原生登录功能");
      }

      // SPA 路由切到 /login 时，尝试插一次
      api.onPageChange((url) => {
        if (url && url.indexOf("/login") !== -1) {
          setTimeout(insertSsoButton, 100);
        }
      });

      // 初次加载就尝试一次（直接访问 /login 的情况）
      setTimeout(insertSsoButton, 100);

      // 监听 DOM 变化（登录弹窗 / 切 tab / 异步渲染等）
      // 注意：只用于插入按钮，不修改任何其他元素
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
