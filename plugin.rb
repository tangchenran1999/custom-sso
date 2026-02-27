# frozen_string_literal: true

# name: custom-sso
# about: 走统一的认证中心实现单点登录
# version: 0.0.4
# authors: tangchenran
# url: https://github.com/tangchenran/custom-sso
# required_version: 2.7.0
# gem: jwt

enabled_site_setting :custom_sso_enabled

after_initialize do
  # ── 1. 加载控制器 ─────────────────────────────────────
  require_relative "app/controllers/custom_sso_controller"

  # ── 2. 注册路由 ──────────────────────────────────────
  #    routes.prepend 把路由插入到路由表最前面（在 catch-all 之前）。
  Discourse::Application.routes.prepend do
    get "/custom-sso/login"         => "custom_sso#login"
    get "/custom-sso/callback"      => "custom_sso#callback"
    get "/custom-sso/authorize"     => "custom_sso#authorize"
    get "/custom-sso/idp_initiated" => "custom_sso#idp_initiated"
  end

  Rails.logger.info("[CustomSSO] Plugin initialized — routes: /custom-sso/{login,callback,authorize,idp_initiated}")
end
