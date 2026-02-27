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
  # SSO 回调必须在用户未登录时也能访问，否则 OAuth 流程会断掉。
  skip_before_action :verify_authenticity_token
  skip_before_action :check_xhr
  skip_before_action :redirect_to_login_if_required
  skip_before_action :ensure_logged_in,          raise: false
  skip_before_action :block_if_requires_login,   raise: false
  skip_before_action :check_site_read_only,      raise: false
  skip_before_action :handle_theme_hierarchies,  raise: false
  skip_before_action :block_if_readonly_mode,    raise: false
  skip_before_action :preload_json,              raise: false

  # 告诉 Discourse 这些 action 允许匿名访问（不需要登录）
  def self.allows_anonymous?
    true
  end

  # ──────────────────────────────────────────────────────────
  # 1️⃣  /custom-sso/login
  #
  #    Discourse 登录页上的「统一身份认证」按钮会跳到这里。
  #    这里的职责很简单：把用户重定向到认证中心的登录页。
  #
  #    完整流程：
  #      Discourse 登录页 → /custom-sso/login
  #        → 认证中心登录页 (custom_sso_login_url)
  #        → 用户登录成功 → 进入门户 (/portal)
  #        → 用户点击"进入系统" → 门户后端 buildLaunchUrl()
  #        → OAuth authorize URL（redirect_uri = /custom-sso/callback）
  #        → 认证中心自动授权（已登录）→ 302 回 /custom-sso/callback?code=xxx
  #        → Discourse callback 处理 → 登录用户 → 跳转首页
  # ──────────────────────────────────────────────────────────
  def login
    login_url = SiteSetting.custom_sso_login_url.to_s.strip

    if login_url.blank?
      Rails.logger.error("CustomSSO: custom_sso_login_url is blank! Please configure it in admin settings.")
      render plain: "统一认证登录地址未配置，请在后台设置 custom_sso_login_url", status: 500
      return
    end

    Rails.logger.info("CustomSSO: login action - redirecting to portal login: #{login_url}")
    redirect_to login_url, allow_other_host: true
  end

  # ──────────────────────────────────────────────────────────
  # 2️⃣  /custom-sso/callback
  #
  #    门户"进入系统"触发的 OAuth 流程最终会回调到这里。
  #    门户后端 buildLaunchUrl() 生成的 authorize URL 中，
  #    redirect_uri 就是指向这个地址。
  #
  #    认证中心授权后会带 code 和 state 参数回来：
  #      GET /custom-sso/callback?code=xxx&state=yyy
  #
  #    本方法的职责：
  #      1. 用 code 换 access_token（POST token_url）
  #      2. 用 access_token 获取用户信息（GET user_info_url）
  #      3. 在 Discourse 中查找或创建用户
  #      4. 登录用户并跳转到首页
  # ──────────────────────────────────────────────────────────
  def callback
    code      = params[:code]
    state     = params[:state]
    idp_token = params[:token].presence

    Rails.logger.info(
      "CustomSSO: callback received — code=#{code.present? ? 'present' : 'missing'}, " \
      "state=#{state.present? ? 'present' : 'missing'}, " \
      "token=#{idp_token.present? ? 'present' : 'missing'}, " \
      "params=#{params.except(:controller, :action).keys.join(', ')}"
    )

    # ── 情况 A：没有任何认证参数 ────────────────────────────
    # 门户的 launchUrl 可能只是一个裸的 /custom-sso/callback（不带参数），
    # 此时需要重新走完整的 OAuth 流程。
    if code.blank? && idp_token.blank? && params[:email].blank? && params[:username].blank? && params[:account].blank?
      Rails.logger.info("CustomSSO: callback has no auth params — starting OAuth flow via /custom-sso/authorize")
      redirect_to "/custom-sso/authorize"
      return
    end

    # ── 情况 B：带了 token（IdP 发起 / 门户直接带 JWT 回跳）──
    email    = nil
    username = nil
    name     = nil

    if idp_token.present?
      begin
        decoded = decode_idp_token(idp_token)
        email    = decoded[:email]    || decoded["email"]
        username = decoded[:username] || decoded["username"] || decoded[:account] || decoded["account"] || decoded[:login] || decoded["login"]
        name     = decoded[:name]     || decoded["name"]     || decoded[:display_name] || decoded["display_name"] || username
        Rails.logger.info("CustomSSO: decoded idp_token — email=#{email}, username=#{username}")
      rescue => e
        Rails.logger.error("CustomSSO: failed to decode idp_token: #{e.class} #{e.message}")
      end
    end

    # ── 情况 C：回调直接带了用户字段 ──────────────────────
    email    ||= params[:email]
    username ||= params[:username] || params[:account] || params[:login]
    name     ||= params[:name]     || params[:display_name] || username

    # ── 情况 D：带了 code，走标准 OAuth code → token → userinfo ──
    if email.blank? || username.blank?
      if code.blank?
        Rails.logger.error("CustomSSO: no code and no usable token/params")
        raise Discourse::InvalidAccess, "缺少授权码且无法获取用户信息"
      end

      token_url     = SiteSetting.custom_sso_token_url.to_s.strip
      user_info_url = SiteSetting.custom_sso_user_info_url.to_s.strip

      if token_url.blank? || user_info_url.blank?
        Rails.logger.error("CustomSSO: token_url or user_info_url not configured")
        raise Discourse::InvalidAccess, "OAuth 配置不完整，请同时配置 custom_sso_token_url 和 custom_sso_user_info_url"
      end

      begin
        access_token = exchange_code_for_token(code, token_url)
        user_info    = fetch_user_info(access_token, user_info_url)

        email    = user_info["email"]    || user_info[:email]
        username = user_info["username"] || user_info[:username] ||
                   user_info["account"]  || user_info[:account]  ||
                   user_info["login"]    || user_info[:login]
        name     = user_info["name"]     || user_info[:name]     ||
                   user_info["display_name"] || user_info[:display_name] ||
                   username

        Rails.logger.info("CustomSSO: got user info from OAuth — email=#{email}, username=#{username}, name=#{name}")
      rescue => e
        Rails.logger.error("CustomSSO: OAuth flow failed: #{e.class} #{e.message}")
        Rails.logger.error(e.backtrace.first(10).join("\n"))
        raise Discourse::InvalidAccess, "获取用户信息失败: #{e.message}"
      end
    end

    if email.blank? || username.blank?
      Rails.logger.error("CustomSSO: still missing email(#{email.inspect}) or username(#{username.inspect})")
      raise Discourse::InvalidAccess, "缺少用户邮箱或用户名"
    end

    # ── 查找或创建 Discourse 用户 ─────────────────────────
    user = find_or_provision_user(email: email, username: username, name: name)

    # ── 登录并跳转 ───────────────────────────────────────
    log_on_user(user)
    Rails.logger.info("CustomSSO: user logged in — user_id=#{user.id}, username=#{user.username}")

    redirect_to "/"
  end

  # ──────────────────────────────────────────────────────────
  # 3️⃣  /custom-sso/authorize
  #
  #    主动发起 OAuth 授权请求。
  #    当 callback 收到无参数请求时（门户 launchUrl 不带 code），
  #    或者需要手动触发 OAuth 流程时，会跳到这里。
  #
  #    这里构造标准的 OAuth 2.0 Authorization Code 请求，
  #    redirect_uri 指回 /custom-sso/callback。
  # ──────────────────────────────────────────────────────────
  def authorize
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
    session[:custom_sso_nonce] = state

    sep = authorize_url.include?("?") ? "&" : "?"
    full_url = "#{authorize_url}#{sep}" \
      "response_type=code" \
      "&client_id=#{CGI.escape(client_id)}" \
      "&scope=#{CGI.escape('openid profile')}" \
      "&redirect_uri=#{CGI.escape(callback_url)}" \
      "&state=#{state}"

    Rails.logger.info("CustomSSO: authorize action — redirecting to: #{full_url}")
    redirect_to full_url, allow_other_host: true
  end

  # ──────────────────────────────────────────────────────────
  # 4️⃣  /custom-sso/idp_initiated
  #
  #    IdP 发起（门户直接带 JWT token 打开 Discourse）。
  #    门户生成 HS256 JWT，包含 email / username / name。
  # ──────────────────────────────────────────────────────────
  def idp_initiated
    unless SiteSetting.custom_sso_idp_initiated_enabled
      raise Discourse::InvalidAccess
    end

    token = params[:token].to_s.presence
    raise Discourse::InvalidAccess, "缺少 token" if token.blank?

    secret = SiteSetting.custom_sso_idp_jwt_secret.to_s.presence
    raise Discourse::InvalidAccess, "未配置 JWT 密钥" if secret.blank?

    begin
      decoded = decode_idp_token(token)
    rescue => e
      Rails.logger.error("CustomSSO: idp_initiated token decode failed: #{e.class} #{e.message}")
      raise Discourse::InvalidAccess, "token 验证失败"
    end

    email    = decoded["email"]    || decoded[:email]
    username = decoded["username"] || decoded[:username] || decoded["account"] || decoded[:account] || decoded["login"] || decoded[:login]
    name     = decoded["name"]     || decoded[:name]     || decoded["display_name"] || decoded[:display_name] || username

    if email.blank? || username.blank?
      Rails.logger.error("CustomSSO: idp_initiated token missing email/username: #{decoded.inspect}")
      raise Discourse::InvalidAccess, "token 缺少 email 或 username"
    end

    user = find_or_provision_user(email: email, username: username, name: name)
    log_on_user(user)

    return_url = safe_return_url(params[:return_url]) || "/"
    redirect_to return_url
  end

  private

  # ── 辅助方法 ────────────────────────────────────────────

  # 优先使用 custom_sso_discourse_base_url（反向代理场景），否则用 Discourse.base_url
  def discourse_base
    custom = SiteSetting.custom_sso_discourse_base_url.to_s.strip
    custom.present? ? custom.chomp("/") : Discourse.base_url
  end

  def safe_return_url(raw)
    return "/" if raw.blank?
    begin
      uri = URI.parse(raw.to_s)
    rescue URI::InvalidURIError
      return "/"
    end

    if uri.scheme.nil? && uri.host.nil? && raw.start_with?("/") && !raw.start_with?("//")
      raw
    else
      "/"
    end
  end

  def decode_idp_token(token)
    secret = SiteSetting.custom_sso_idp_jwt_secret.to_s.presence
    issuer = SiteSetting.custom_sso_idp_issuer.to_s.presence
    raise Discourse::InvalidAccess, "未配置 JWT 密钥" if secret.blank?

    decode_opts = {
      algorithm: "HS256",
      verify_expiration: true,
      verify_not_before: false,
      verify_iat: false,
    }
    if issuer
      decode_opts[:iss] = issuer
      decode_opts[:verify_iss] = true
    end

    decoded, = ::JWT.decode(token, secret, true, decode_opts)
    decoded.with_indifferent_access
  end

  # 用 code 换取 access_token（POST 请求到 token_url）
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
      grant_type:   "authorization_code",
      code:         code,
      redirect_uri: callback_url,
      client_id:    client_id,
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

  # 用 access_token 获取用户信息（GET 请求到 user_info_url）
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

  # 查找或创建 Discourse 用户
  def find_or_provision_user(email:, username:, name:)
    normalized_username = normalize_username(username)
    normalized_email    = email.to_s.strip.downcase

    # 优先按用户名匹配，其次按邮箱兜底
    user = User.find_by(username: normalized_username) || User.find_by(email: normalized_email)

    if user
      begin
        user.name  = name.to_s if name.present? && user.name.to_s != name.to_s
        user.email = normalized_email if normalized_email.present? &&
                                          user.email.to_s.downcase != normalized_email &&
                                          !User.exists?(email: normalized_email)
        user.save! if user.changed?
      rescue => e
        Rails.logger.warn("CustomSSO: failed to sync user fields: user_id=#{user.id}, err=#{e.class}: #{e.message}")
      end

      Rails.logger.info("CustomSSO: found existing user — id=#{user.id}, email=#{normalized_email}, username=#{normalized_username}")
      return user
    end

    final_username = ensure_unique_username(normalized_username)
    password = SecureRandom.hex(32)

    user = User.create!(
      email:                 normalized_email,
      username:              final_username,
      name:                  name.present? ? name.to_s : final_username,
      password:              password,
      password_confirmation: password,
      active:                true,
      approved:              true
    )

    Rails.logger.info("CustomSSO: created new user — id=#{user.id}, email=#{normalized_email}, username=#{final_username}")
    user
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
end
