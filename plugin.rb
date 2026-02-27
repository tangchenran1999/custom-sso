# frozen_string_literal: true

# name: custom-sso
# about: 走统一的认证中心实现单点登录
# version: 0.0.1
# authors: tangchenran
# url: https://github.com/tangchenran/custom-sso
# required_version: 2.7.0
# gem: jwt

enabled_site_setting :custom_sso_enabled

after_initialize do
  # ── 1. 加载控制器 ─────────────────────────────────────
  #    控制器文件里的类必须是 ::CustomSsoController（顶层命名空间），
  #    这样 Rails 路由 "custom_sso#login" 才能找到它。
  require_relative "app/controllers/custom_sso_controller"

  # ── 2. 注册路由 ──────────────────────────────────────
  #    用 Discourse::Application.routes.draw 把路由画进主应用。
  #    这是 Discourse 插件注册自定义路由最可靠的方式。
  Discourse::Application.routes.draw do
    get "/custom-sso/login"         => "custom_sso#login"
    get "/custom-sso/callback"      => "custom_sso#callback"
    get "/custom-sso/idp_initiated" => "custom_sso#idp_initiated"
  end
end
