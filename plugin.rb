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
  #    ⚠️ 必须用 routes.prepend（而不是 routes.draw 或 routes.append）！
  #    Discourse 有一个 catch-all 路由 `get "*path" => "application#index"`
  #    会匹配所有未知路径并返回 Ember.js 的 HTML 页面。
  #    routes.draw 会清除已有路由，routes.append 会把路由加在 catch-all 之后，
  #    只有 routes.prepend 才能把路由加在 catch-all 之前，确保被优先匹配。
  Discourse::Application.routes.prepend do
    get "/custom-sso/login"         => "custom_sso#login"
    get "/custom-sso/callback"      => "custom_sso#callback"
    get "/custom-sso/idp_initiated" => "custom_sso#idp_initiated"
  end
end
