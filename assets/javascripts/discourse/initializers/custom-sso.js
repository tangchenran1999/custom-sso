import { withPluginApi } from "discourse/lib/plugin-api";

// ══════════════════════════════════════════════════════════════════
// 🔒 最早期拦截：在 Discourse Ember 路由器之前拦截 history API
//    防止登录成功后 Ember 通过 pushState 导航到 /custom-sso/login
//    这段代码必须在模块加载时立即执行（不能等 withPluginApi 回调）
// ══════════════════════════════════════════════════════════════════
(function earlyIntercept() {
  // 检查 URL 是否指向 /custom-sso/login（不含 callback 等其他路由）
  function isBadSsoRedirect(url) {
    if (typeof url !== "string") {
      return false;
    }
    try {
      // 处理相对路径和绝对路径
      const parsed = new URL(url, window.location.origin);
      return parsed.pathname === "/custom-sso/login" || parsed.pathname.startsWith("/custom-sso/login?");
    } catch (_) {
      return url === "/custom-sso/login" || url.startsWith("/custom-sso/login?") || url.startsWith("/custom-sso/login#");
    }
  }

  function fixUrl(url) {
    if (typeof url !== "string") {
      return url;
    }
    try {
      const parsed = new URL(url, window.location.origin);
      parsed.pathname = "/";
      return parsed.pathname + parsed.search + parsed.hash;
    } catch (_) {
      return "/";
    }
  }

  const _origPushState = history.pushState;
  const _origReplaceState = history.replaceState;

  history.pushState = function (state, title, url) {
    if (isBadSsoRedirect(url)) {
      // eslint-disable-next-line no-console
      console.warn("[custom-sso][early] intercepted pushState to /custom-sso/login → rewriting to /");
      url = fixUrl(url);
    }
    return _origPushState.call(this, state, title, url);
  };

  history.replaceState = function (state, title, url) {
    if (isBadSsoRedirect(url)) {
      // eslint-disable-next-line no-console
      console.warn("[custom-sso][early] intercepted replaceState to /custom-sso/login → rewriting to /");
      url = fixUrl(url);
    }
    return _origReplaceState.call(this, state, title, url);
  };

  // 如果页面已经在 /custom-sso/login 上（例如硬刷新或直接访问）
  // 且 Discourse 的 session cookie 存在（说明用户已登录），直接跳首页
  if (window.location.pathname === "/custom-sso/login" && document.cookie.includes("_t=")) {
    // eslint-disable-next-line no-console
    console.warn("[custom-sso][early] already on /custom-sso/login and logged in → redirecting to /");
    window.location.replace("/");
  }
})();

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
      //    需要区分两种情况：
      //    A) 用户已登录 → 直接跳首页（不要再走 SSO 流程）
      //    B) 用户未登录 → 强制全页面刷新让 Rails 处理
      const path = window.location.pathname;
      if (
        path.startsWith("/custom-sso/callback") ||
        path.startsWith("/custom-sso/complete-profile") ||
        path.startsWith("/custom-sso/create-account")
      ) {
        // 这些路由始终需要后端处理
        // eslint-disable-next-line no-console
        console.log("[custom-sso] backend route detected, forcing full page navigation");
        if (!window.location.search.includes("_sso_reload=1")) {
          const sep = window.location.search ? "&" : "?";
          window.location.href = window.location.href + sep + "_sso_reload=1";
          return;
        }
        return;
      }

      if (path === "/custom-sso/login" || path.startsWith("/custom-sso/login?")) {
        // /custom-sso/login 需要特殊处理
        if (document.cookie.includes("_t=")) {
          // 用户已登录，直接跳首页（不要走 SSO 流程）
          // eslint-disable-next-line no-console
          console.warn("[custom-sso] on /custom-sso/login but already logged in → redirecting to /");
          window.location.replace("/");
          return;
        }
        // 用户未登录，强制全页面刷新让 Rails 处理 SSO
        // eslint-disable-next-line no-console
        console.log("[custom-sso] backend route /custom-sso/login detected, forcing full page navigation");
        if (!window.location.search.includes("_sso_reload=1")) {
          const sep = window.location.search ? "&" : "?";
          window.location.href = window.location.href + sep + "_sso_reload=1";
          return;
        }
        return;
      }

      // ── popstate 监听（浏览器前进/后退按钮）────────
      window.addEventListener("popstate", () => {
        if (window.location.pathname === "/custom-sso/login") {
          // eslint-disable-next-line no-console
          console.warn("[custom-sso] detected navigation to /custom-sso/login via popstate → redirecting to /");
          window.location.replace("/");
        }
      });

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
