import { withPluginApi } from "discourse/lib/plugin-api";

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("custom-sso initializer loaded");

      // 通过 DI 读到站点设置（包括插件自定义的设置）
      let siteSettings = null;
      try {
        siteSettings = api.container.lookup("site-settings:main");
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn(
          "custom-sso: failed to lookup site-settings",
          e
        );
      }

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

          // 直接做全页面跳转到后端 login 路由，
          // 后端会生成 nonce 并 redirect 到认证中心
          // 用绝对路径 + origin 确保不被 SPA 路由拦截
          const loginPath = window.location.origin + "/custom-sso/login";
          // eslint-disable-next-line no-console
          console.log("custom-sso: navigating to", loginPath);
          window.location.replace(loginPath);
        });

        // 放到最前面
        container.prepend(btn);

        // eslint-disable-next-line no-console
        console.log("custom-sso button inserted");
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
