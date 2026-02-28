# frozen_string_literal: true

# name: custom-sso
# about: 走统一的认证中心实现单点登录
# version: 0.1.0
# authors: tangchenran
# url: https://github.com/tangchenran/custom-sso
# required_version: 2.7.0
# gem: jwt

enabled_site_setting :custom_sso_enabled

after_initialize do
  # ── 1. 加载控制器 ─────────────────────────────────────
  require_relative "app/controllers/custom_sso_controller"

  # ── 2. 注册路由 ──────────────────────────────────────
  Discourse::Application.routes.prepend do
    scope "/custom-sso", defaults: { format: :html } do
      get  "login"            => "custom_sso#login"
      get  "callback"         => "custom_sso#callback"
      get  "complete-profile" => "custom_sso#complete_profile"
      post "create-account"   => "custom_sso#create_account"
    end
  end

  # ══════════════════════════════════════════════════════════
  # 3. 防止原生登录成功后跳转到 /custom-sso/login
  #
  # 问题根因：
  #   用户点击"统一身份认证"→ 浏览器全页面跳转到 /custom-sso/login
  #   → Discourse 中间件/before_action 把这个 URL 存到
  #     session["destination_url"]
  #   → 用户没完成 SSO，回到 Discourse 用原生方式登录
  #   → SessionController#create 读取 session["destination_url"]
  #     返回给前端
  #   → 前端跳转到 /custom-sso/login → 404
  #
  # 解决方案（三层防护）：
  #
  #   层1: 在 ApplicationController 的 before_action 中清除
  #        session["destination_url"]（如果它指向 /custom-sso/）
  #        → 这会在 SessionController#create 执行前运行
  #
  #   层2: 直接 monkey-patch SessionController#create，
  #        在调用 super 之前清除 session["destination_url"]
  #        → 确保万无一失
  #
  #   层3: 前端拦截 DiscourseURL.routeTo/redirectTo
  #        → 即使后端漏了，前端也能兜住
  # ══════════════════════════════════════════════════════════

  # ── 层1: ApplicationController before_action ──────────
  ApplicationController.class_eval do
    before_action :_custom_sso_sanitize_destination_url

    private

    def _custom_sso_sanitize_destination_url
      dest = session["destination_url"].to_s
      if dest.include?("/custom-sso/")
        Rails.logger.info("[CustomSSO] Layer1: Clearing bad destination_url from session: #{dest}")
        session.delete("destination_url")
      end
    rescue => e
      Rails.logger.warn("[CustomSSO] Layer1 error: #{e.message}")
    end
  end

  # ── 层2: 直接 patch SessionController#create ─────────
  #
  #    SessionController#create 是 Discourse 原生登录的入口。
  #    登录成功后它会读取 session["destination_url"] 并放到
  #    JSON 响应的 redirect_url 字段中。
  #
  #    我们在它执行之前再清一次，确保万无一失。
  #    同时在执行之后也检查响应体，如果 redirect_url 包含
  #    /custom-sso/ 就替换为 /。
  #
  if defined?(::SessionController)
    ::SessionController.class_eval do
      # 保存原始方法
      alias_method :_original_create_without_sso_fix, :create

      def create
        # 在调用原始 create 之前，清除 session 中的 /custom-sso/ URL
        dest = session["destination_url"].to_s
        if dest.include?("/custom-sso/")
          Rails.logger.info("[CustomSSO] Layer2-pre: Clearing destination_url before SessionController#create: #{dest}")
          session.delete("destination_url")
        end

        # 调用原始的 create 方法
        _original_create_without_sso_fix

        # 在调用原始 create 之后，检查响应体
        # SessionController#create 返回 JSON，其中可能包含 redirect_url
        begin
          if response.content_type&.include?("json") && response.body.present?
            body = JSON.parse(response.body)
            redirect_url = body["redirect_url"].to_s
            if redirect_url.include?("/custom-sso/")
              Rails.logger.info("[CustomSSO] Layer2-post: Fixing redirect_url in response: #{redirect_url} → /")
              body["redirect_url"] = "/"
              self.response_body = [body.to_json]
            end
          end
        rescue => e
          Rails.logger.warn("[CustomSSO] Layer2-post error: #{e.message}")
        end
      end
    end
    Rails.logger.info("[CustomSSO] Layer2: Patched SessionController#create")
  else
    Rails.logger.warn("[CustomSSO] Layer2: SessionController not defined, skipping patch")
  end

  Rails.logger.info("[CustomSSO] Plugin initialized — routes: /custom-sso/{login,callback,complete-profile,create-account}")
end
