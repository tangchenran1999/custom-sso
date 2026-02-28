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
  #    使用 prepend 确保优先于 Discourse 的 catch-all 路由。
  #    添加 constraints 确保只匹配 HTML 格式请求。
  Discourse::Application.routes.prepend do
    # 所有 /custom-sso/* 路由都指向 CustomSsoController
    scope "/custom-sso", defaults: { format: :html } do
      get  "login"            => "custom_sso#login"
      get  "callback"         => "custom_sso#callback"
      get  "complete-profile" => "custom_sso#complete_profile"
      post "create-account"   => "custom_sso#create_account"
    end
  end

  # ── 3. 清除 session 中指向 /custom-sso/login 的 destination_url ──
  #    Discourse 在用户未登录时访问某个页面会把该 URL 保存到
  #    session["destination_url"]，登录成功后跳转到该 URL。
  #    如果用户之前访问过 /custom-sso/login，这个 URL 会被保存，
  #    导致原生登录成功后跳转到 /custom-sso/login（显示 404）。
  #    这里在每次请求时检查并清除这个值。
  ApplicationController.class_eval do
    before_action :sanitize_custom_sso_destination_url

    private

    def sanitize_custom_sso_destination_url
      dest = session["destination_url"].to_s
      if dest.include?("/custom-sso/login")
        Rails.logger.warn("[CustomSSO] Cleared session destination_url that pointed to /custom-sso/login: #{dest}")
        session.delete("destination_url")
      end
    rescue => e
      # 不要因为这个检查影响正常请求
      Rails.logger.warn("[CustomSSO] Error in sanitize_custom_sso_destination_url: #{e.message}")
    end
  end

  Rails.logger.info("[CustomSSO] Plugin initialized — routes: /custom-sso/{login,callback,complete-profile,create-account}")
end
