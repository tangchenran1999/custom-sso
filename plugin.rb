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
  # ── 加载控制器 ─────────────────────────────────────
  require_relative "app/controllers/custom_sso_controller"

  # ── 注册路由 ──────────────────────────────────────
  # 注意：路由名称故意避开 "login" 这个词！
  # Discourse 的 ApplicationController 会把包含 "login" 的 URL 存入
  # session["destination_url"]，原生登录成功后会跳转到那个 URL。
  # 如果 SSO 入口路由叫 /custom-sso/login，原生登录成功后就会被错误地
  # 跳转到 SSO 流程，导致两套登录互相干扰。
  # 所以 SSO 入口改名为 /custom-sso/authorize。
  Discourse::Application.routes.prepend do
    scope "/custom-sso", defaults: { format: :html } do
      get  "authorize"        => "custom_sso#authorize"
      get  "callback"         => "custom_sso#callback"
      get  "complete-profile" => "custom_sso#complete_profile"
      post "create-account"   => "custom_sso#create_account"
    end
  end

  # ── 全局拦截：防止 /custom-sso/* 被存入 destination_url ──
  # Discourse 的 ApplicationController 会在 before_action 中把当前请求 URL
  # 存到 session["destination_url"]，用于登录后跳转。
  # 我们必须确保 /custom-sso/* 的 URL 永远不会出现在 destination_url 中，
  # 否则原生登录成功后会被错误地跳转到 SSO 流程。
  # 这个拦截在 ApplicationController 级别生效，覆盖所有请求。
  reloadable_patch do |plugin|
    ::ApplicationController.class_eval do
      after_action :_sanitize_destination_url_for_custom_sso

      private

      def _sanitize_destination_url_for_custom_sso
        dest = session["destination_url"].to_s
        if dest.include?("/custom-sso/")
          Rails.logger.info("[CustomSSO] Removing /custom-sso/ URL from destination_url: #{dest}")
          session.delete("destination_url")
        end
      end
    end
  end

  Rails.logger.info("[CustomSSO] Plugin initialized — routes: /custom-sso/{authorize,callback,complete-profile,create-account}")
end
