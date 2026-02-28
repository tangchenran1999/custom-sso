import { withPluginApi } from "discourse/lib/plugin-api";
import DiscourseURL from "discourse/lib/url";

// ══════════════════════════════════════════════════════════════════
// 🔒 最早期拦截（多层防护）
//    防止原生登录成功后跳转到 /custom-sso/login
//
//    Discourse 原生登录流程：
//    1. 前端 AJAX POST /session → 后端返回 JSON { destination_url: "/custom-sso/login" }
//    2. 前端调用 DiscourseURL.routeTo(destination_url) 或 window.location = destination_url
//    3. Ember 路由器找不到 /custom-sso/login → 显示 404
//
//    我们需要在多个层面拦截：
//    A) history.pushState / replaceState（Ember 内部路由）
//    B) DiscourseURL.routeTo / redirectTo（Discourse 的跳转 API）
//    C) window.location 赋值（全页面跳转的最后防线）
// ══════════════════════════════════════════════════════════════════

// 判断 URL 是否指向 /custom-sso/login
function _isBadSsoUrl(url) {
  if (typeof url !== "string") {
    return false;
  }
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.pathname === "/custom-sso/login";
  } catch (_) {
    return (
      url === "/custom-sso/login" ||
      url.startsWith("/custom-sso/login?") ||
      url.startsWith("/custom-sso/login#")
    );
  }
}

// ── A) 拦截 history.pushState / replaceState ──────────────────
(function earlyIntercept() {
  const _origPushState = history.pushState;
  const _origReplaceState = history.replaceState;

  history.pushState = function (state, title, url) {
    if (_isBadSsoUrl(url)) {
      // eslint-disable-next-line no-console
      console.warn("[custom-sso][early] intercepted pushState to /custom-sso/login → rewriting to /");
      url = "/";
    }
    return _origPushState.call(this, state, title, url);
  };

  history.replaceState = function (state, title, url) {
    if (_isBadSsoUrl(url)) {
      // eslint-disable-next-line no-console
      console.warn("[custom-sso][early] intercepted replaceState to /custom-sso/login → rewriting to /");
      url = "/";
    }
    return _origReplaceState.call(this, state, title, url);
  };

  // 如果页面已经在 /custom-sso/login 上且用户已登录，直接跳首页
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

      // ── B) 拦截 DiscourseURL.routeTo / redirectTo ──────────
      //    Discourse 原生登录成功后，前端通过 DiscourseURL.routeTo(destination_url)
      //    跳转到 session["destination_url"]。如果这个值是 /custom-sso/login，
      //    Ember 路由器找不到对应路由就会显示 404。
      //    这里拦截 DiscourseURL 的方法，把 /custom-sso/login 改写为 /。
      try {
        if (DiscourseURL) {
          const _origRouteTo = DiscourseURL.routeTo;
          if (_origRouteTo) {
            DiscourseURL.routeTo = function (url, opts) {
              if (_isBadSsoUrl(url)) {
                // eslint-disable-next-line no-console
                console.warn("[custom-sso] intercepted DiscourseURL.routeTo(/custom-sso/login) → rewriting to /");
                return _origRouteTo.call(this, "/", opts);
              }
              return _origRouteTo.call(this, url, opts);
            };
          }

          const _origRedirectTo = DiscourseURL.redirectTo;
          if (_origRedirectTo) {
            DiscourseURL.redirectTo = function (url) {
              if (_isBadSsoUrl(url)) {
                // eslint-disable-next-line no-console
                console.warn("[custom-sso] intercepted DiscourseURL.redirectTo(/custom-sso/login) → rewriting to /");
                return _origRedirectTo.call(this, "/");
              }
              return _origRedirectTo.call(this, url);
            };
          }

          // eslint-disable-next-line no-console
          console.log("[custom-sso] DiscourseURL.routeTo/redirectTo interceptors installed");
        }
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn("[custom-sso] failed to intercept DiscourseURL methods:", e);
      }

      // ── C) 如果当前 URL 是 /custom-sso/* 后端路由 ──────────
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

      if (path === "/custom-sso/login") {
        // /custom-sso/login 需要特殊处理
        if (document.cookie.includes("_t=")) {
          // 用户已登录，直接跳首页
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

      // ── D) 监听页面变化，如果 Ember 路由到了 /custom-sso/login 就重定向 ──
      api.onPageChange((url) => {
        if (url && (url === "/custom-sso/login" || url.startsWith("/custom-sso/login?"))) {
          // eslint-disable-next-line no-console
          console.warn("[custom-sso] onPageChange detected /custom-sso/login → redirecting to /");
          DiscourseURL.routeTo("/");
        }
      });

      // ── popstate 监听（浏览器前进/后退按钮）────────
      window.addEventListener("popstate", () => {
        if (window.location.pathname === "/custom-sso/login") {
          // eslint-disable-next-line no-console
          console.warn("[custom-sso] detected navigation to /custom-sso/login via popstate → redirecting to /");
          window.location.replace("/");
        }
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
        btn.setAttribute("data-custom-sso", "true");
        btn.style.marginBottom = "10px";

        // 只监听 SSO 按钮的点击事件
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();

          // eslint-disable-next-line no-console
          console.log("[custom-sso] 用户点击了统一身份认证按钮");
          
          // 使用全页面导航跳转到 SSO 登录（不经过 pushState，不会被拦截）
          window.location.href = window.location.origin + "/custom-sso/login";
        });

        // 插入到容器最前面
        container.prepend(btn);

        // eslint-disable-next-line no-console
        console.log("[custom-sso] SSO 按钮已插入");
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
