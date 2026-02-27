import { withPluginApi } from "discourse/lib/plugin-api";

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("custom-sso initializer loaded (no widgets)");

      // 通过 DI 读到站点设置（包括插件自定义的设置），失败就用 null 并走默认值
      let siteSettings = null;
      try {
        siteSettings = api.container.lookup("site-settings:main");
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn(
          "custom-sso: failed to lookup site-settings, using default login url",
          e
        );
      }

      function insertSsoButton() {
        // 已经有就不重复插
        if (document.querySelector(".custom-sso-btn")) {
          return;
        }

        // 尝试找到登录按钮容器（新版本里一般还是叫 .login-buttons）
        const container =
          document.querySelector(".login-buttons") ||
          document.querySelector(".auth-buttons");

        if (!container) {
          return;
        }

        const a = document.createElement("a");
        a.className = "btn btn-primary custom-sso-btn";

        // 点击按钮先经过插件的登录路由，由后端处理回调URL和nonce
        a.href = "/custom-sso/login";

        // 调试日志：看看按钮最终 href 是什么
        // eslint-disable-next-line no-console
        console.log("custom-sso: final SSO login href =", a.href);
        a.textContent = "统一身份认证";
        // 非常关键：禁止 Discourse 的 SPA 自动路由拦截这个链接
        // 不然它会去请求 /permalink-check.json，而不是直接访问 /custom_sso/login
        a.setAttribute("data-auto-route", "false");
        // 兜底：如果某些版本不认 data-auto-route，就手动强制整页跳转
        a.addEventListener("click", (e) => {
          e.preventDefault();
          window.location.href = a.href;
        });

        // 放到最前面
        container.prepend(a);

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