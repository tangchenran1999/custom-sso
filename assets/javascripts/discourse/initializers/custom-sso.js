import { withPluginApi } from "discourse/lib/plugin-api";
import DiscourseURL from "discourse/lib/url";

// ══════════════════════════════════════════════════════════════════
// custom-sso 插件前端初始化
//
// 功能：
//   1. 在登录弹窗中插入"统一身份认证"按钮
//   2. 防止原生登录成功后错误跳转到 /custom-sso/login
//
// 三层防护（后端 + 前端）：
//   后端层1: plugin.rb — ApplicationController before_action 清除 session
//   后端层2: plugin.rb — patch SessionController#create 清除 + 修改响应
//   前端层3: 本文件 — 拦截 DiscourseURL.routeTo/redirectTo/handleURL
//
// "统一身份认证"按钮使用 window.location.href 全页面跳转，
//   不经过 DiscourseURL.routeTo，所以不会被拦截。
// ══════════════════════════════════════════════════════════════════

/**
 * 判断 URL 是否是 /custom-sso/login
 */
function _isSsoLoginUrl(url) {
  if (typeof url !== "string") return false;
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

/**
 * 包装一个函数，如果第一个参数是 /custom-sso/login 就替换为 /
 */
function _wrapUrlMethod(original, methodName) {
  if (typeof original !== "function") return original;
  return function (url, ...rest) {
    if (_isSsoLoginUrl(url)) {
      // eslint-disable-next-line no-console
      console.warn(
        `[custom-sso] blocked ${methodName}('${url}') → redirecting to /`
      );
      return original.call(this, "/", ...rest);
    }
    return original.call(this, url, ...rest);
  };
}

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded");

      // ────────────────────────────────────────────────────────
      // 1. 拦截 DiscourseURL 的所有跳转方法
      //
      //    Discourse 前端登录成功后，可能通过以下任一方法跳转：
      //    - DiscourseURL.routeTo(url)
      //    - DiscourseURL.redirectTo(url)
      //    - DiscourseURL.handleURL(url)
      //    - DiscourseURL.replaceState(url)
      //
      //    全部拦截，如果目标是 /custom-sso/login 就改为 /
      // ────────────────────────────────────────────────────────
      try {
        const methods = ["routeTo", "redirectTo", "handleURL", "replaceState"];
        for (const m of methods) {
          if (typeof DiscourseURL[m] === "function") {
            DiscourseURL[m] = _wrapUrlMethod(DiscourseURL[m], `DiscourseURL.${m}`);
          }
        }
        // eslint-disable-next-line no-console
        console.log("[custom-sso] DiscourseURL intercept installed for:", methods.join(", "));
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn("[custom-sso] failed to install DiscourseURL intercept:", e);
      }

      // ────────────────────────────────────────────────────────
      // 2. 兜底：如果 Ember 路由变化到了 /custom-sso/login，
      //    强制全页面跳转到首页
      // ────────────────────────────────────────────────────────
      api.onPageChange((url) => {
        if (url && _isSsoLoginUrl(url)) {
          // eslint-disable-next-line no-console
          console.warn(
            "[custom-sso] onPageChange detected /custom-sso/login → redirecting to /"
          );
          window.location.replace("/");
        }
      });

      // ────────────────────────────────────────────────────────
      // 3. 在登录弹窗中插入"统一身份认证"按钮
      // ────────────────────────────────────────────────────────
      function insertSsoButton() {
        // 已经插入过就跳过
        if (document.querySelector(".custom-sso-btn")) return;

        // 找到登录弹窗中的按钮容器
        const container =
          document.querySelector(".login-buttons") ||
          document.querySelector(".auth-buttons");
        if (!container) return;

        const btn = document.createElement("button");
        btn.className = "btn btn-primary custom-sso-btn";
        btn.type = "button";
        btn.textContent = "统一身份认证";
        btn.style.cssText = "margin-bottom:10px;width:100%;";

        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          // eslint-disable-next-line no-console
          console.log(
            "[custom-sso] SSO button clicked → navigating to /custom-sso/login"
          );
          // 全页面跳转，不经过 DiscourseURL.routeTo，不会被拦截
          window.location.href = window.location.origin + "/custom-sso/login";
        });

        container.prepend(btn);
        // eslint-disable-next-line no-console
        console.log("[custom-sso] SSO button inserted");
      }

      // 页面切换到 /login 时尝试插入按钮
      api.onPageChange((url) => {
        if (url && url.indexOf("/login") !== -1) {
          setTimeout(insertSsoButton, 100);
        }
      });

      // 初次加载尝试一次
      setTimeout(insertSsoButton, 100);

      // 监听 DOM 变化（登录弹窗是异步渲染的）
      const observer = new MutationObserver(() => insertSsoButton());
      observer.observe(document.body, { childList: true, subtree: true });
    });
  },
};
