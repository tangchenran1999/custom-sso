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
  Discourse::Application.routes.prepend do
    scope "/custom-sso", defaults: { format: :html } do
      get  "login"            => "custom_sso#login"
      get  "callback"         => "custom_sso#callback"
      get  "complete-profile" => "custom_sso#complete_profile"
      post "create-account"   => "custom_sso#create_account"
    end
  end

  Rails.logger.info("[CustomSSO] Plugin initialized — routes: /custom-sso/{login,callback,complete-profile,create-account}")
end
