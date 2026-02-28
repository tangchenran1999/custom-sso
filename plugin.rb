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

  # ── 3. 从根源阻止 destination_url 指向 /custom-sso/login ──
  #
  #    问题：Discourse 在用户未登录时访问某个页面，会把该 URL 存到
  #    session["destination_url"]。原生登录成功后，SessionController
  #    返回这个 URL 给前端，前端跳转过去。
  #
  #    如果用户曾访问过 /custom-sso/login（比如点了"统一身份认证"
  #    但没完成登录就回来了），这个 URL 就会被存下来，导致原生登录
  #    成功后跳转到 /custom-sso/login（Ember 前端没有这个路由 → 404）。
  #
  #    解决：在每次请求的 before_action 中检查并清除它。
  #    这样 SessionController#create 返回的 JSON 中就不会包含
  #    /custom-sso/login 作为 destination_url。
  #
  #    注意：这个 before_action 加在 ApplicationController 上，
  #    所有控制器都会继承，包括 SessionController。
  #
  ApplicationController.class_eval do
    before_action :_custom_sso_sanitize_destination_url

    private

    def _custom_sso_sanitize_destination_url
      dest = session["destination_url"].to_s
      if dest.include?("/custom-sso/")
        Rails.logger.info("[CustomSSO] Clearing bad destination_url from session: #{dest}")
        session.delete("destination_url")
      end
    rescue => e
      Rails.logger.warn("[CustomSSO] Error in _custom_sso_sanitize_destination_url: #{e.message}")
    end
  end

  Rails.logger.info("[CustomSSO] Plugin initialized — routes: /custom-sso/{login,callback,complete-profile,create-account}")
end
