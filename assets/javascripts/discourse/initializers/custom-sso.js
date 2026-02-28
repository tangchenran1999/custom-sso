import { withPluginApi } from "discourse/lib/plugin-api";

export default {
  name: "custom-sso",

  initialize() {
    withPluginApi("1.0.0", (api) => {
      // eslint-disable-next-line no-console
      console.log("[custom-sso] initializer loaded, path:", window.location.pathname);

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
        // 使用 document.location.href 赋值触发完整页面加载
        // 加一个 _t 参数防止缓存，同时作为标记防止无限循环
        if (!window.location.search.includes("_sso_reload=1")) {
          const sep = window.location.search ? "&" : "?";
          window.location.href =
            window.location.href + sep + "_sso_reload=1";
          return;
        }
        // 如果已经有 _sso_reload=1 还是到了这里，说明路由确实没注册成功
        // 不做任何事，让 Ember 显示 404 页面
        return;
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

        // ── 关键保护：确保不会修改或影响原生登录表单 ────────
        // 查找所有登录表单，确保它们的action属性不被修改
        const loginForms = document.querySelectorAll('form[action*="/login"], form[action*="/session"]');
        loginForms.forEach((form) => {
          // 确保表单的action属性不被修改
          const originalAction = form.getAttribute("action");
          if (originalAction && !originalAction.includes("/custom-sso/")) {
            // 如果表单的action被错误地修改了，恢复它
            if (form.getAttribute("data-original-action")) {
              form.setAttribute("action", form.getAttribute("data-original-action"));
            } else {
              // 保存原始action，以防万一
              form.setAttribute("data-original-action", originalAction);
            }
          }
        });

        const btn = document.createElement("button");
        btn.className = "btn btn-primary custom-sso-btn";
        btn.type = "button"; // 关键：type="button" 确保不会触发表单提交
        btn.textContent = "统一身份认证";
        // 添加明确的标识，避免与原生登录按钮混淆
        btn.setAttribute("data-custom-sso", "true");
        btn.style.marginBottom = "10px"; // 添加间距，与原生按钮区分

        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();

          // eslint-disable-next-line no-console
          console.log("[custom-sso] 用户点击了统一身份认证按钮，跳转到 SSO 登录");
          
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

        // ── 额外保护：监听表单提交，确保原生登录表单不会被错误提交到 /custom-sso/login ────────
        loginForms.forEach((form) => {
          form.addEventListener("submit", (e) => {
            const formAction = form.getAttribute("action") || form.action;
            // eslint-disable-next-line no-console
            console.log("[custom-sso] 检测到表单提交，action:", formAction);
            
            // 如果表单的action被错误地设置为 /custom-sso/login，阻止提交并恢复
            if (formAction && formAction.includes("/custom-sso/login")) {
              // eslint-disable-next-line no-console
              console.error("[custom-sso] 错误：原生登录表单的action被设置为 /custom-sso/login，已阻止并恢复");
              e.preventDefault();
              e.stopPropagation();
              
              // 恢复原始action
              const originalAction = form.getAttribute("data-original-action");
              if (originalAction) {
                form.setAttribute("action", originalAction);
                // eslint-disable-next-line no-console
                console.log("[custom-sso] 已恢复表单action为:", originalAction);
              } else {
                // 如果没有保存原始action，使用默认的Discourse登录路径
                form.setAttribute("action", "/session");
                // eslint-disable-next-line no-console
                console.log("[custom-sso] 已设置表单action为默认值: /session");
              }
              
              return false;
            }
          }, true); // 使用捕获阶段，确保优先处理
        });

        // eslint-disable-next-line no-console
        console.log("[custom-sso] button inserted - 注意：此按钮仅用于统一身份认证，不影响原生登录/注册功能");
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
