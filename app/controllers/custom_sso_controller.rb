# frozen_string_literal: true

# 注意：类名必须是 CustomSsoController（顶层命名空间），
# 这样 Rails 路由 "custom_sso#login" 才能正确匹配到这个控制器。
class CustomSsoController < ::ApplicationController
  requires_plugin "custom-sso"

  require "net/http"
  require "json"
  require "openssl"
  require "uri"

  # ── 跳过所有可能阻止匿名访问的 before_action ──────────
  skip_before_action :verify_authenticity_token
  skip_before_action :check_xhr
  skip_before_action :redirect_to_login_if_required
  skip_before_action :ensure_logged_in,          raise: false
  skip_before_action :block_if_requires_login,   raise: false
  skip_before_action :check_site_read_only,      raise: false
  skip_before_action :handle_theme_hierarchies,  raise: false
  skip_before_action :block_if_readonly_mode,    raise: false
  skip_before_action :preload_json,              raise: false

  def self.allows_anonymous?
    true
  end

  # ──────────────────────────────────────────────────────────
  # 1️⃣  GET /custom-sso/login
  #
  #    Discourse 登录页上的「统一身份认证」按钮会跳到这里。
  #    直接构造 OAuth 2.0 Authorization Code 请求，
  #    跳转到认证中心的 authorize 端点。
  #
  #    如果用户未在认证中心登录，认证中心会自动展示登录页面；
  #    登录成功后认证中心会带 code 回调到 /custom-sso/callback。
  #    全程不经过门户 portal 页面。
  # ──────────────────────────────────────────────────────────
  def login
    authorize_url = SiteSetting.custom_sso_authorize_url.to_s.strip
    client_id     = SiteSetting.custom_sso_client_id.to_s.strip
    callback_url  = "#{discourse_base}/custom-sso/callback"

    if authorize_url.blank?
      Rails.logger.error("CustomSSO: custom_sso_authorize_url is blank!")
      render plain: "OAuth 授权端点未配置，请在后台设置 custom_sso_authorize_url", status: 500
      return
    end

    if client_id.blank?
      Rails.logger.error("CustomSSO: custom_sso_client_id is blank!")
      render plain: "OAuth client_id 未配置，请在后台设置 custom_sso_client_id", status: 500
      return
    end

    state = SecureRandom.hex(16)
    session[:custom_sso_state] = state

    sep = authorize_url.include?("?") ? "&" : "?"
    full_url = "#{authorize_url}#{sep}" \
      "response_type=code" \
      "&client_id=#{CGI.escape(client_id)}" \
      "&scope=#{CGI.escape('openid profile')}" \
      "&redirect_uri=#{CGI.escape(callback_url)}" \
      "&state=#{state}"

    Rails.logger.info("CustomSSO: login action — redirecting to OAuth authorize: #{full_url}")
    redirect_to full_url, allow_other_host: true
  end

  # ──────────────────────────────────────────────────────────
  # 2️⃣  GET /custom-sso/callback?code=xxx&state=yyy
  #
  #    认证中心授权后带 code 回调到这里。
  #
  #    流程：
  #      1. 用 code 换 access_token
  #      2. 用 access_token 获取用户信息
  #      3. 在 Discourse 中查找用户：
  #         - 已存在 → 直接登录，跳转首页
  #         - 不存在 → 首次登录，创建用户（临时邮箱），
  #                    跳转到补全信息页面
  # ──────────────────────────────────────────────────────────
  def callback
    code  = params[:code].to_s.strip
    state = params[:state].to_s.strip

    Rails.logger.info(
      "CustomSSO: callback received — code=#{code.present? ? 'present' : 'missing'}, " \
      "state=#{state.present? ? 'present' : 'missing'}"
    )

    if code.blank?
      Rails.logger.error("CustomSSO: callback missing code param")
      raise Discourse::InvalidAccess, "缺少授权码 (code)"
    end

    # ── 用 code 换 token，再获取用户信息 ──────────────────
    token_url     = SiteSetting.custom_sso_token_url.to_s.strip
    user_info_url = SiteSetting.custom_sso_user_info_url.to_s.strip

    if token_url.blank? || user_info_url.blank?
      Rails.logger.error("CustomSSO: token_url or user_info_url not configured")
      raise Discourse::InvalidAccess, "OAuth 配置不完整，请配置 token_url 和 user_info_url"
    end

    begin
      access_token = exchange_code_for_token(code, token_url)
      user_info    = fetch_user_info(access_token, user_info_url)

      username = user_info["username"] || user_info[:username] ||
                 user_info["account"]  || user_info[:account]  ||
                 user_info["login"]    || user_info[:login]    ||
                 user_info["sub"]      || user_info[:sub]
      email    = user_info["email"]    || user_info[:email]
      name     = user_info["name"]     || user_info[:name]     ||
                 user_info["display_name"] || user_info[:display_name] ||
                 username

      Rails.logger.info("CustomSSO: got user info — email=#{email}, username=#{username}, name=#{name}")
    rescue => e
      Rails.logger.error("CustomSSO: OAuth flow failed: #{e.class} #{e.message}")
      Rails.logger.error(e.backtrace.first(10).join("\n"))
      raise Discourse::InvalidAccess, "获取用户信息失败: #{e.message}"
    end

    if username.blank?
      Rails.logger.error("CustomSSO: username is blank after OAuth flow")
      raise Discourse::InvalidAccess, "认证中心未返回用户名"
    end

    normalized_username = normalize_username(username)

    # ── 查找已有用户 ──────────────────────────────────────
    existing_user = User.find_by(username: normalized_username)
    existing_user ||= User.find_by(email: email.to_s.strip.downcase) if email.present?

    if existing_user
      # ── 已有用户：直接登录 ──────────────────────────────
      Rails.logger.info("CustomSSO: found existing user — id=#{existing_user.id}, username=#{existing_user.username}")

      # 同步 name（如果有变化）
      begin
        existing_user.name = name.to_s if name.present? && existing_user.name.to_s != name.to_s
        existing_user.save! if existing_user.changed?
      rescue => e
        Rails.logger.warn("CustomSSO: failed to sync user fields: #{e.message}")
      end

      log_on_user(existing_user)
      redirect_to "/"
    else
      # ── 新用户：首次登录，需要补全邮箱和设置密码 ────────
      Rails.logger.info("CustomSSO: new user detected — username=#{normalized_username}, redirecting to complete profile")

      # 把认证信息存到 session 中，供 complete_profile 页面使用
      session[:sso_pending_username] = normalized_username
      session[:sso_pending_name]     = name.to_s.presence || normalized_username
      session[:sso_pending_email]    = email.to_s.strip.downcase if email.present?

      redirect_to "/custom-sso/complete-profile"
    end
  end

  # ──────────────────────────────────────────────────────────
  # 3️⃣  GET /custom-sso/complete-profile
  #
  #    首次登录的用户需要补全邮箱和设置密码。
  #    显示一个简单的表单页面。
  # ──────────────────────────────────────────────────────────
  def complete_profile
    username = session[:sso_pending_username]
    if username.blank?
      redirect_to "/login"
      return
    end

    name  = session[:sso_pending_name] || username
    email = session[:sso_pending_email] || ""

    # 渲染一个独立的 HTML 页面（不走 Ember）
    render html: complete_profile_html(username, name, email).html_safe, layout: false
  end

  # ──────────────────────────────────────────────────────────
  # 4️⃣  POST /custom-sso/create-account
  #
  #    接收补全信息表单提交，创建用户并登录。
  # ──────────────────────────────────────────────────────────
  def create_account
    username = session[:sso_pending_username]
    name     = session[:sso_pending_name]

    if username.blank?
      raise Discourse::InvalidAccess, "会话已过期，请重新登录"
    end

    email    = params[:email].to_s.strip.downcase
    password = params[:password].to_s

    # ── 验证 ──────────────────────────────────────────────
    if email.blank? || !email.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      render html: complete_profile_html(username, name, email, "请输入有效的邮箱地址").html_safe, layout: false
      return
    end

    if password.length < 8
      render html: complete_profile_html(username, name, email, "密码长度至少 8 位").html_safe, layout: false
      return
    end

    if User.exists?(email: email)
      render html: complete_profile_html(username, name, email, "该邮箱已被其他用户使用").html_safe, layout: false
      return
    end

    # ── 创建用户 ──────────────────────────────────────────
    final_username = ensure_unique_username(username)

    begin
      user = User.create!(
        email:                 email,
        username:              final_username,
        name:                  name.present? ? name.to_s : final_username,
        password:              password,
        password_confirmation: password,
        active:                true,
        approved:              true
      )

      Rails.logger.info("CustomSSO: created new user — id=#{user.id}, email=#{email}, username=#{final_username}")

      # 清除 session 中的临时数据
      session.delete(:sso_pending_username)
      session.delete(:sso_pending_name)
      session.delete(:sso_pending_email)

      log_on_user(user)
      redirect_to "/"
    rescue => e
      Rails.logger.error("CustomSSO: failed to create user: #{e.class} #{e.message}")
      render html: complete_profile_html(username, name, email, "创建用户失败: #{e.message}").html_safe, layout: false
    end
  end

  private

  # ── 辅助方法 ────────────────────────────────────────────

  def discourse_base
    custom = SiteSetting.custom_sso_discourse_base_url.to_s.strip
    custom.present? ? custom.chomp("/") : Discourse.base_url
  end

  def exchange_code_for_token(code, token_url)
    callback_url  = "#{discourse_base}/custom-sso/callback"
    client_id     = SiteSetting.custom_sso_client_id.to_s
    client_secret = SiteSetting.custom_sso_client_secret.to_s

    uri  = URI.parse(token_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl

    request = Net::HTTP::Post.new(uri.request_uri)
    request.set_form_data(
      grant_type:    "authorization_code",
      code:          code,
      redirect_uri:  callback_url,
      client_id:     client_id,
      client_secret: client_secret
    )

    Rails.logger.info("CustomSSO: exchanging code for token at #{token_url}")
    response = http.request(request)

    unless response.is_a?(Net::HTTPSuccess)
      Rails.logger.error("CustomSSO: token exchange failed — #{response.code} #{response.message}")
      Rails.logger.error("CustomSSO: response body: #{response.body}")
      raise "Token 交换失败: #{response.code} #{response.message}"
    end

    result = JSON.parse(response.body)
    access_token = result["access_token"] || result[:access_token]

    if access_token.blank?
      Rails.logger.error("CustomSSO: no access_token in response: #{result.inspect}")
      raise "Token 响应中缺少 access_token"
    end

    Rails.logger.info("CustomSSO: successfully got access_token")
    access_token
  rescue JSON::ParserError => e
    Rails.logger.error("CustomSSO: failed to parse token response: #{e.message}")
    raise "Token 响应解析失败: #{e.message}"
  end

  def fetch_user_info(access_token, user_info_url)
    uri  = URI.parse(user_info_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl

    request = Net::HTTP::Get.new(uri.request_uri)
    request["Authorization"] = "Bearer #{access_token}"
    request["Accept"]        = "application/json"

    Rails.logger.info("CustomSSO: fetching user info from #{user_info_url}")
    response = http.request(request)

    unless response.is_a?(Net::HTTPSuccess)
      Rails.logger.error("CustomSSO: user info fetch failed — #{response.code} #{response.message}")
      Rails.logger.error("CustomSSO: response body: #{response.body}")
      raise "获取用户信息失败: #{response.code} #{response.message}"
    end

    result = JSON.parse(response.body)
    Rails.logger.info("CustomSSO: user info response: #{result.inspect}")
    result
  rescue JSON::ParserError => e
    Rails.logger.error("CustomSSO: failed to parse user info response: #{e.message}")
    raise "用户信息响应解析失败: #{e.message}"
  end

  def normalize_username(username)
    u = username.to_s.strip
    u = u.gsub(/\s+/, "_")
    u = u.gsub(/[^A-Za-z0-9_\.]/, "_")
    u = u[0, 60]
    u = "user" if u.blank?
    u
  end

  def ensure_unique_username(base)
    candidate = base
    return candidate unless User.exists?(username: candidate)

    20.times do
      candidate = "#{base}_#{SecureRandom.random_number(10_000)}"
      return candidate unless User.exists?(username: candidate)
    end

    "#{base}_#{SecureRandom.hex(4)}"
  end

  # ── 补全信息页面 HTML ──────────────────────────────────
  def complete_profile_html(username, name, email, error_msg = nil)
    base_url = discourse_base
    <<~HTML
      <!DOCTYPE html>
      <html lang="zh-CN">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>完善账户信息</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f6f7;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
          }
          .card {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 16px rgba(0,0,0,0.10);
            padding: 40px 36px;
            width: 100%;
            max-width: 420px;
          }
          .card h2 {
            text-align: center;
            margin-bottom: 8px;
            color: #222;
            font-size: 22px;
          }
          .card .subtitle {
            text-align: center;
            color: #888;
            font-size: 14px;
            margin-bottom: 28px;
          }
          .field { margin-bottom: 20px; }
          .field label {
            display: block;
            font-size: 14px;
            color: #555;
            margin-bottom: 6px;
            font-weight: 500;
          }
          .field input {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 15px;
            outline: none;
            transition: border-color 0.2s;
          }
          .field input:focus {
            border-color: #0078d4;
            box-shadow: 0 0 0 2px rgba(0,120,212,0.15);
          }
          .field input[readonly] {
            background: #f3f4f6;
            color: #888;
            cursor: not-allowed;
          }
          .error-msg {
            background: #fef2f2;
            color: #dc2626;
            border: 1px solid #fecaca;
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 14px;
            margin-bottom: 20px;
          }
          .submit-btn {
            width: 100%;
            padding: 12px;
            background: #0078d4;
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
          }
          .submit-btn:hover { background: #005a9e; }
          .submit-btn:active { background: #004578; }
          .tip {
            text-align: center;
            margin-top: 16px;
            font-size: 13px;
            color: #999;
          }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>完善账户信息</h2>
          <p class="subtitle">首次通过统一身份认证登录，请补全以下信息</p>

          #{error_msg ? "<div class=\"error-msg\">#{ERB::Util.html_escape(error_msg)}</div>" : ""}

          <form method="POST" action="#{base_url}/custom-sso/create-account">
            <div class="field">
              <label>用户名</label>
              <input type="text" value="#{ERB::Util.html_escape(username)}" readonly />
            </div>

            <div class="field">
              <label>显示名称</label>
              <input type="text" value="#{ERB::Util.html_escape(name)}" readonly />
            </div>

            <div class="field">
              <label>邮箱 <span style="color:#dc2626">*</span></label>
              <input type="email" name="email" value="#{ERB::Util.html_escape(email)}"
                     placeholder="请输入您的邮箱地址" required />
            </div>

            <div class="field">
              <label>设置密码 <span style="color:#dc2626">*</span></label>
              <input type="password" name="password" placeholder="至少 8 位" minlength="8" required />
            </div>

            <button type="submit" class="submit-btn">完成注册并登录</button>
          </form>

          <p class="tip">密码用于后续直接登录 Discourse（也可以始终使用统一身份认证登录）</p>
        </div>
      </body>
      </html>
    HTML
  end
end
