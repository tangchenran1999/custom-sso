# frozen_string_literal: true

# name: custom-sso
# about: 走统一的认证中心实现单点登录
# version: 0.0.3
# authors: tangchenran
# url: https://github.com/tangchenran/custom-sso
# required_version: 2.7.0
# gem: jwt

enabled_site_setting :custom_sso_enabled

# ── 在 after_initialize 之前注册路由 ──────────────────
# 这是 Discourse 插件注册自定义路由最可靠的方式。
# 在 plugin.rb 顶层直接调用 register_asset / register_route 等 API。
# 但 Discourse 没有 register_route API，所以我们用 Rails 标准方式。

after_initialize do
  # ── 1. 加载控制器 ─────────────────────────────────────
  require_relative "app/controllers/custom_sso_controller"

  # ── 2. 注册路由 ──────────────────────────────────────
  #    Discourse 有一个 catch-all 路由 `get "*path" => "application#index"`
  #    会匹配所有未知路径并返回 Ember.js 的 HTML 页面。
  #
  #    routes.prepend 会把路由插入到路由表的最前面（在 catch-all 之前）。
  #    这是 Discourse 插件注册自定义路由的标准方式。
  #
  #    ⚠️ 如果路由仍然不生效，可能需要 rebuild 容器：
  #       ./launcher rebuild app
  Discourse::Application.routes.prepend do
    get "/custom-sso/login"         => "custom_sso#login"
    get "/custom-sso/callback"      => "custom_sso#callback"
    get "/custom-sso/idp_initiated" => "custom_sso#idp_initiated"
  end

  Rails.logger.info("CustomSSO: Plugin initialized, routes registered for /custom-sso/*")
end
