import { withPluginApi } from "discourse/lib/plugin-api";

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded");

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

        const btn = document.createElement("button");
        btn.className = "btn btn-primary custom-sso-btn";
        btn.type = "button";
        btn.textContent = "统一身份认证";

        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();

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

        // eslint-disable-next-line no-console
        console.log("[custom-sso] button inserted");
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
