import { withPluginApi } from "discourse/lib/plugin-api";
import DiscourseURL from "discourse/lib/url";

// ══════════════════════════════════════════════════════════════════
// custom-sso 插件前端初始化
//
// 功能：
//   1. 在登录弹窗中插入"统一身份认证"按钮
//   2. 防止原生登录成功后错误跳转到 /custom-sso/login
//
// 问题背景：
//   Discourse 会把用户登录前访问的 URL 存到 session["destination_url"]，
//   登录成功后跳转到该 URL。如果用户曾访问过 /custom-sso/login，
//   原生登录成功后就会跳到 /custom-sso/login，但 Ember 前端没有
//   这个路由，导致 404。
//
// 解决方案：
//   后端：在 plugin.rb 中清除 session 里的 /custom-sso/login
//   前端：拦截 DiscourseURL.routeTo，防止跳转到 /custom-sso/login
//
// "统一身份认证"按钮使用 window.location.href 全页面跳转，
//   不经过 DiscourseURL.routeTo，所以不会被拦截。
// ══════════════════════════════════════════════════════════════════

/**
 * 判断 URL 是否是 /custom-sso/login（不含其他 /custom-sso/* 路径）
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

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded");

      // ────────────────────────────────────────────────────────
      // 1. 拦截 DiscourseURL.routeTo / redirectTo
      //    原生登录成功后，Discourse 前端调用：
      //      DiscourseURL.routeTo(destination_url)
      //    如果 destination_url 是 /custom-sso/login，改写为 /
      //
      //    "统一身份认证"按钮使用 window.location.href 跳转，
      //    不经过这里，所以不受影响。
      // ────────────────────────────────────────────────────────
      try {
        const _origRouteTo = DiscourseURL.routeTo;
        if (typeof _origRouteTo === "function") {
          DiscourseURL.routeTo = function (url, opts) {
            if (_isSsoLoginUrl(url)) {
              // eslint-disable-next-line no-console
              console.warn(
                "[custom-sso] blocked DiscourseURL.routeTo('/custom-sso/login') → redirecting to /"
              );
              return _origRouteTo.call(this, "/", opts);
            }
            return _origRouteTo.call(this, url, opts);
          };
        }

        const _origRedirectTo = DiscourseURL.redirectTo;
        if (typeof _origRedirectTo === "function") {
          DiscourseURL.redirectTo = function (url) {
            if (_isSsoLoginUrl(url)) {
              // eslint-disable-next-line no-console
              console.warn(
                "[custom-sso] blocked DiscourseURL.redirectTo('/custom-sso/login') → redirecting to /"
              );
              return _origRedirectTo.call(this, "/");
            }
            return _origRedirectTo.call(this, url);
          };
        }

        // eslint-disable-next-line no-console
        console.log("[custom-sso] DiscourseURL intercept installed");
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn("[custom-sso] failed to install DiscourseURL intercept:", e);
      }

      // ────────────────────────────────────────────────────────
      // 2. 兜底：如果 Ember 路由变化到了 /custom-sso/login，重定向到首页
      //    这是最后一道防线，正常情况下不会触发。
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
        btn.type = "button"; // type="button" 不会触发表单提交
        btn.textContent = "统一身份认证";
        btn.style.cssText = "margin-bottom:10px;width:100%;";

        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          // eslint-disable-next-line no-console
          console.log("[custom-sso] SSO button clicked → navigating to /custom-sso/login");
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
