import { withPluginApi } from "discourse/lib/plugin-api";

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded");

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
