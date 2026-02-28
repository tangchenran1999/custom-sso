import { withPluginApi } from "discourse/lib/plugin-api";

// ══════════════════════════════════════════════════════════════════
// custom-sso 插件前端初始化
//
// 功能：在登录弹窗/页面中插入"统一身份认证"按钮
//
// 两套登录流程互不干扰：
//   - 统一身份认证：点击按钮 → 全页面跳转 /custom-sso/authorize → OAuth 流程
//   - 原生登录：Discourse 自带的用户名/密码登录，完全不受影响
//
// 注意：SSO 入口路由故意避开 "login" 这个词！
// Discourse 会把包含 "login" 的 URL 存入 session["destination_url"]，
// 原生登录成功后会跳转到那个 URL，导致两套登录互相干扰。
// ══════════════════════════════════════════════════════════════════

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded");

      // ────────────────────────────────────────────────────────
      // 在登录弹窗中插入"统一身份认证"按钮
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
        btn.className = "btn btn-large btn-primary custom-sso-btn";
        btn.type = "button";
        btn.textContent = "统一身份认证";
        btn.style.cssText = "margin-bottom:10px;width:100%;";

        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          // eslint-disable-next-line no-console
          console.log(
            "[custom-sso] SSO button clicked → navigating to /custom-sso/authorize"
          );
          // 全页面跳转到 SSO 登录入口（路径用 authorize 而非 login，避免冲突）
          window.location.href =
            window.location.origin + "/custom-sso/authorize";
        });

        container.prepend(btn);
        // eslint-disable-next-line no-console
        console.log("[custom-sso] SSO button inserted");
      }

      // 页面切换到 /login 时尝试插入按钮
      // 注意：只匹配 Discourse 原生的 /login 路径，不匹配 /custom-sso/*
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
