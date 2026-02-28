# frozen_string_literal: true

# 注意：类名必须是 CustomSsoController（顶层命名空间），
# 这样 Rails 路由 "custom_sso#login" 才能正确匹配到这个控制器。
class CustomSsoController < ::ApplicationController
  requires_plugin "custom-sso"

  require "net/http"
  require "json"
  require "openssl"
  require "uri"
  require "base64"

  # ── 跳过所有可能阻止匿名访问的 before_action ──────────
  # 这些路由必须对未登录用户开放（OAuth 回调时用户尚未在 Discourse 登录）
  skip_before_action :verify_authenticity_token
  skip_before_action :check_xhr
  skip_before_action :redirect_to_login_if_required
  skip_before_action :ensure_logged_in,            raise: false
  skip_before_action :block_if_requires_login,     raise: false
  skip_before_action :check_site_read_only,        raise: false
  skip_before_action :handle_theme_hierarchies,    raise: false
  skip_before_action :block_if_readonly_mode,      raise: false
  skip_before_action :preload_json,                raise: false
  skip_before_action :force_https,                 raise: false
  skip_before_action :check_restricted_access,     raise: false
  skip_before_action :block_if_maintenance_mode,   raise: false

  # 允许匿名访问（Discourse 内部检查）
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
    Rails.logger.info("CustomSSO: ========== login action entered ==========")
    Rails.logger.info("CustomSSO: request method=#{request.method}, format=#{request.format}")
    Rails.logger.info("CustomSSO: request url=#{request.original_url}")
    Rails.logger.info("CustomSSO: current_user=#{current_user&.username || 'anonymous'}")
    
    # 如果用户已经登录，先登出，然后再进行 SSO 登录
    if current_user
      Rails.logger.info("CustomSSO: user already logged in (#{current_user.username}), logging out first")
      log_off_user
      Rails.logger.info("CustomSSO: user logged out, proceeding with SSO login")
    end
    
    authorize_url = SiteSetting.custom_sso_authorize_url.to_s.strip
    client_id     = SiteSetting.custom_sso_client_id.to_s.strip
    callback_url  = "#{discourse_base}/custom-sso/callback"

    Rails.logger.info("CustomSSO: authorize_url=#{authorize_url}, client_id=#{client_id.present? ? 'present' : 'blank'}")

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

    # 生成 state 和 nonce（OpenID Connect 标准参数）
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    
    # 使用 Redis 存储 state 和 nonce（避免跨域重定向导致 session 丢失）
    # 设置 10 分钟过期时间
    redis_key = "custom_sso_state:#{state}"
    redis_data = { nonce: nonce, created_at: Time.now.to_i }.to_json
    Discourse.redis.setex(redis_key, 600, redis_data) # 600 秒 = 10 分钟

    Rails.logger.info("CustomSSO: login — discourse_base=#{discourse_base}, callback_url=#{callback_url}")
    Rails.logger.info("CustomSSO: state=#{state}, nonce=#{nonce}")
    Rails.logger.info("CustomSSO: saved state to Redis with key=#{redis_key}")

    # 使用 URI 构建器确保 URL 格式正确
    # 这样可以正确处理已有查询参数，避免重复
    uri = URI.parse(authorize_url)
    query_params = {}
    
    # 解析已有查询参数
    if uri.query.present?
      URI.decode_www_form(uri.query).each do |key, value|
        query_params[key] = value
      end
    end
    
    # 添加/覆盖 OAuth 参数
    query_params["response_type"] = "code"
    query_params["client_id"] = client_id
    query_params["scope"] = "openid profile"
    query_params["redirect_uri"] = callback_url
    query_params["state"] = state
    query_params["nonce"] = nonce
    
    uri.query = URI.encode_www_form(query_params)
    full_url = uri.to_s

    Rails.logger.info("CustomSSO: login action — redirecting to OAuth authorize: #{full_url}")
    
    # 使用 302 重定向，确保浏览器正确处理 cookie 和 session
    redirect_to full_url, allow_other_host: true, status: 302
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
    Rails.logger.info("CustomSSO: ========== callback action entered ==========")
    Rails.logger.info("CustomSSO: request format=#{request.format}, xhr=#{request.xhr?}, method=#{request.method}")
    Rails.logger.info("CustomSSO: request url=#{request.original_url}")
    Rails.logger.info("CustomSSO: discourse_base=#{discourse_base}")
    Rails.logger.info("CustomSSO: params=#{params.to_unsafe_h.except(:code).inspect}")

    code  = params[:code].to_s.strip
    state = params[:state].to_s.strip
    nonce = params[:nonce].to_s.strip

    Rails.logger.info(
      "CustomSSO: callback received — code=#{code.present? ? 'present' : 'missing'}, " \
      "state=#{state.present? ? state : 'missing'}, " \
      "nonce=#{nonce.present? ? 'present' : 'missing'}"
    )

    if code.blank?
      Rails.logger.error("CustomSSO: callback missing code param")
      render plain: "缺少授权码 (code)，请重新登录", status: 400
      return
    end

    # 验证 state（防止 CSRF 攻击）
    # 从 Redis 中读取 state（避免跨域重定向导致 session 丢失）
    if state.blank?
      Rails.logger.error("CustomSSO: state is blank in callback")
      render plain: "授权状态验证失败：回调中缺少 state 参数，请重新登录", status: 400
      return
    end
    
    redis_key = "custom_sso_state:#{state}"
    redis_data = Discourse.redis.get(redis_key)
    
    if redis_data.blank?
      Rails.logger.error("CustomSSO: state not found in Redis — key=#{redis_key}, state may be expired or invalid")
      render plain: "授权状态验证失败：state 已过期或无效，请重新登录", status: 400
      return
    end
    
    begin
      state_info = JSON.parse(redis_data)
      expected_nonce = state_info["nonce"]
      Rails.logger.info("CustomSSO: state validation — found in Redis, nonce=#{expected_nonce}")
      
      # 验证 nonce（如果回调中提供了 nonce）
      if nonce.present? && expected_nonce.present? && nonce != expected_nonce
        Rails.logger.error("CustomSSO: nonce mismatch — expected=#{expected_nonce}, got=#{nonce}")
        Discourse.redis.del(redis_key) # 删除已使用的 state
        render plain: "授权状态验证失败：nonce 不匹配，请重新登录", status: 400
        return
      end
      
      # 验证成功，删除 Redis 中的 state（一次性使用）
      Discourse.redis.del(redis_key)
      Rails.logger.info("CustomSSO: state validated successfully, removed from Redis")
    rescue JSON::ParserError => e
      Rails.logger.error("CustomSSO: failed to parse Redis data: #{e.message}")
      Discourse.redis.del(redis_key)
      render plain: "授权状态验证失败：数据格式错误，请重新登录", status: 400
      return
    end

    # ── 用 code 换 token，再获取用户信息 ──────────────────
    token_url     = SiteSetting.custom_sso_token_url.to_s.strip
    user_info_url = SiteSetting.custom_sso_user_info_url.to_s.strip

    if token_url.blank? || user_info_url.blank?
      Rails.logger.error("CustomSSO: token_url or user_info_url not configured")
      render plain: "OAuth 配置不完整，请配置 token_url 和 user_info_url", status: 500
      return
    end

    begin
      access_token = exchange_code_for_token(code, token_url)

      # ── 优先从 JWT access_token 中解析用户信息 ──────────
      # Spring Authorization Server 的 access_token 是 JWT，
      # 包含 sub, account, realName, userId, authorities 等 claims。
      # /userinfo 端点可能只返回 sub，信息不全，所以优先用 JWT。
      jwt_claims = decode_jwt_payload(access_token)
      Rails.logger.info("CustomSSO: JWT claims: #{jwt_claims.inspect}")

      # 也尝试从 /userinfo 获取补充信息
      user_info = {}
      begin
        user_info = fetch_user_info(access_token, user_info_url)
      rescue => e
        Rails.logger.warn("CustomSSO: userinfo fetch failed (non-fatal): #{e.message}")
      end

      # 合并 JWT claims 和 userinfo，JWT 优先
      merged = user_info.merge(jwt_claims) { |_key, ui_val, jwt_val| jwt_val.present? ? jwt_val : ui_val }

      username = merged["account"]  || merged["username"] ||
                 merged["login"]    || merged["sub"]       ||
                 merged["preferred_username"]
      email    = merged["email"]
      name     = merged["realName"] || merged["real_name"] ||
                 merged["name"]     || merged["display_name"] ||
                 username

      Rails.logger.info("CustomSSO: got user info — email=#{email}, username=#{username}, name=#{name}")
    rescue => e
      Rails.logger.error("CustomSSO: OAuth flow failed: #{e.class} #{e.message}")
      Rails.logger.error(e.backtrace.first(10).join("\n"))
      render plain: "获取用户信息失败: #{e.message}", status: 502
      return
    end

    if username.blank?
      Rails.logger.error("CustomSSO: username is blank after OAuth flow")
      render plain: "认证中心未返回用户名", status: 502
      return
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
      Rails.logger.info("CustomSSO: log_on_user done for #{existing_user.username}, redirecting to #{discourse_base}")
      redirect_to "#{discourse_base}/", allow_other_host: true
    else
      # ── 新用户：首次登录，需要补全邮箱和设置密码 ────────
      Rails.logger.info("CustomSSO: new user detected — username=#{normalized_username}, redirecting to complete profile")

      # 使用 Redis 存储临时用户信息（避免跨域重定向导致 session 丢失）
      # 生成一个唯一的 token，用于后续页面获取用户信息
      profile_token = SecureRandom.hex(32)
      redis_key = "custom_sso_profile:#{profile_token}"
      profile_data = {
        username: normalized_username,
        name: name.to_s.presence || normalized_username,
        email: email.to_s.strip.downcase
      }.to_json
      
      # 设置 15 分钟过期时间（足够用户填写表单）
      Discourse.redis.setex(redis_key, 900, profile_data) # 900 秒 = 15 分钟
      
      Rails.logger.info("CustomSSO: saved profile data to Redis with key=#{redis_key}")

      redirect_to "/custom-sso/complete-profile?token=#{profile_token}"
    end
  end

  # ──────────────────────────────────────────────────────────
  # 3️⃣  GET /custom-sso/complete-profile?token=xxx
  #
  #    首次登录的用户需要补全邮箱和设置密码。
  #    显示一个简单的表单页面。
  # ──────────────────────────────────────────────────────────
  def complete_profile
    profile_token = params[:token].to_s.strip
    
    if profile_token.blank?
      Rails.logger.error("CustomSSO: complete_profile missing token param")
      redirect_to "/login"
      return
    end

    # 从 Redis 中读取用户信息
    redis_key = "custom_sso_profile:#{profile_token}"
    redis_data = Discourse.redis.get(redis_key)
    
    if redis_data.blank?
      Rails.logger.error("CustomSSO: profile token not found in Redis — key=#{redis_key}, token may be expired or invalid")
      redirect_to "/login"
      return
    end

    begin
      profile_data = JSON.parse(redis_data)
      username = profile_data["username"]
      name     = profile_data["name"] || username
      email    = profile_data["email"] || ""
      
      Rails.logger.info("CustomSSO: loaded profile data from Redis — username=#{username}")
      
      # 将 token 传递给表单，以便 create_account 使用
      render html: complete_profile_html(username, name, email, nil, profile_token).html_safe, layout: false
    rescue JSON::ParserError => e
      Rails.logger.error("CustomSSO: failed to parse profile data: #{e.message}")
      redirect_to "/login"
      return
    end
  end

  # ──────────────────────────────────────────────────────────
  # 4️⃣  POST /custom-sso/create-account
  #
  #    接收补全信息表单提交，创建用户并登录。
  # ──────────────────────────────────────────────────────────
  def create_account
    profile_token = params[:token].to_s.strip
    username = nil
    name = nil
    email = nil
    
    begin
      if profile_token.blank?
        render plain: "缺少验证令牌，请重新登录", status: 400
        return
      end

      # 从 Redis 中读取用户信息
      redis_key = "custom_sso_profile:#{profile_token}"
      redis_data = Discourse.redis.get(redis_key)
      
      if redis_data.blank?
        render plain: "验证令牌已过期或无效，请重新登录", status: 400
        return
      end

      begin
        profile_data = JSON.parse(redis_data)
        username = profile_data["username"]
        name     = profile_data["name"] || username
      rescue JSON::ParserError => e
        Rails.logger.error("CustomSSO: failed to parse profile data: #{e.message}")
        render plain: "数据解析失败，请重新登录", status: 400
        return
      end

      # 从表单获取用户输入（用户名来自认证平台，不可修改）
      email    = params[:email].to_s.strip.downcase
      password = params[:password].to_s

      # 用户名从 Redis 中获取（来自认证平台），不允许修改
      final_username = username

      # ── 验证邮箱 ──────────────────────────────────────────
      if email.blank? || !email.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
        render html: complete_profile_html(username, name, email, "请输入有效的邮箱地址", profile_token).html_safe, layout: false
        return
      end

      # ── 验证密码 ──────────────────────────────────────────
      if password.length < 8
        render html: complete_profile_html(username, name, email, "密码长度至少 8 位", profile_token).html_safe, layout: false
        return
      end

      # ── 检查用户名和邮箱是否已存在 ────────────────────────
      if User.exists?(username: final_username)
        render html: complete_profile_html(username, name, email, "该用户名已被使用，请联系管理员", profile_token).html_safe, layout: false
        return
      end

      if User.exists?(email: email)
        render html: complete_profile_html(username, name, email, "该邮箱已被其他用户使用", profile_token).html_safe, layout: false
        return
      end

      # ── 创建用户 ──────────────────────────────────────────
      Rails.logger.info("CustomSSO: attempting to create user — email=#{email}, username=#{final_username}, name=#{name}")
      
      # 使用 Discourse 的 UserCreator 服务创建用户
      # 第一个参数是当前用户（nil 表示系统创建），第二个参数是用户属性
      # 注意：需要提供 ip_address，否则可能报错
      ip_address = begin
        request.remote_ip
      rescue => e
        Rails.logger.warn("CustomSSO: failed to get remote_ip: #{e.message}")
        "127.0.0.1"
      end
      
      user_params = {
        email: email,
        username: final_username,
        name: name,
        password: password,
        password_required: true,
        active: true,
        approved: true,
        skip_email_validation: false,
        ip_address: ip_address
      }
      
      Rails.logger.info("CustomSSO: UserCreator params: #{user_params.except(:password).inspect}")
      
      # 确保使用正确的 UserCreator 类
      creator_class = defined?(::UserCreator) ? ::UserCreator : UserCreator
      Rails.logger.info("CustomSSO: Using UserCreator class: #{creator_class}")
      
      creator = creator_class.new(nil, user_params)
      
      Rails.logger.info("CustomSSO: UserCreator initialized, calling create...")
      result = creator.create
      
      Rails.logger.info("CustomSSO: UserCreator.create returned — success=#{result.success?}, user=#{result.user&.id}")
      
      unless result.success?
        error_message = result.errors.full_messages.join(", ")
        Rails.logger.error("CustomSSO: UserCreator failed — #{error_message}")
        Rails.logger.error("CustomSSO: UserCreator result: #{result.inspect}")
        if result.errors.respond_to?(:full_messages)
          Rails.logger.error("CustomSSO: UserCreator errors: #{result.errors.full_messages.inspect}")
        end
        render html: complete_profile_html(username, name, email, "创建用户失败: #{error_message}", profile_token).html_safe, layout: false
        return
      end
      
      user = result.user
      
      unless user
        Rails.logger.error("CustomSSO: UserCreator returned success but user is nil")
        Rails.logger.error("CustomSSO: UserCreator result object: #{result.inspect}")
        render html: complete_profile_html(username, name, email, "创建用户失败: 用户对象为空", profile_token).html_safe, layout: false
        return
      end
      
      Rails.logger.info("CustomSSO: created new user — id=#{user.id}, email=#{email}, username=#{final_username}, name=#{name}")

      # 清除 Redis 中的临时数据
      Discourse.redis.del(redis_key)
      Rails.logger.info("CustomSSO: deleted profile data from Redis — key=#{redis_key}")

      # 自动登录用户
      Rails.logger.info("CustomSSO: attempting to log in user...")
      log_on_user(user)
      Rails.logger.info("CustomSSO: user logged in automatically after account creation — username=#{final_username}")
      
      Rails.logger.info("CustomSSO: redirecting to #{discourse_base}/")
      redirect_to "#{discourse_base}/", allow_other_host: true
    rescue => e
      Rails.logger.error("CustomSSO: exception in create_account — #{e.class}: #{e.message}")
      Rails.logger.error("CustomSSO: backtrace: #{e.backtrace.first(20).join("\n")}")
      error_msg = "创建用户失败: #{e.class} - #{e.message}"
      begin
        render html: complete_profile_html(username || "unknown", name || "unknown", email || "", error_msg, profile_token).html_safe, layout: false
      rescue => render_error
        Rails.logger.error("CustomSSO: failed to render error page: #{render_error.message}")
        render plain: error_msg, status: 500
      end
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
    client_id     = SiteSetting.custom_sso_client_id.to_s.strip
    client_secret = SiteSetting.custom_sso_client_secret.to_s.strip

    uri = URI.parse(token_url)
    is_ssl = (uri.scheme == "https")

    Rails.logger.info("CustomSSO: exchanging code for token at #{token_url} (ssl=#{is_ssl})")
    Rails.logger.info("CustomSSO: redirect_uri=#{callback_url}, client_id=#{client_id}")

    response = Net::HTTP.start(uri.host, uri.port, use_ssl: is_ssl, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      request = Net::HTTP::Post.new(uri.request_uri)
      request.content_type = "application/x-www-form-urlencoded"

      # Spring Authorization Server 默认使用 client_secret_basic 认证方式
      # 即通过 HTTP Basic Auth 传递 client_id 和 client_secret
      request.basic_auth(client_id, client_secret)

      request.set_form_data(
        "grant_type"   => "authorization_code",
        "code"         => code,
        "redirect_uri" => callback_url
      )
      http.request(request)
    end

    Rails.logger.info("CustomSSO: token response status=#{response.code}")
    Rails.logger.info("CustomSSO: token response body=#{response.body}")

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

  # 解析 JWT 的 payload 部分（不验证签名，仅提取 claims）
  # Spring Authorization Server 的 access_token 是 JWT，
  # 包含 sub, account, realName, userId 等自定义 claims
  def decode_jwt_payload(token)
    parts = token.to_s.split(".")
    return {} unless parts.length == 3

    # JWT payload 是 Base64url 编码的
    payload_b64 = parts[1]
    # 补齐 Base64 padding
    payload_b64 += "=" * (4 - payload_b64.length % 4) if payload_b64.length % 4 != 0
    payload_json = Base64.urlsafe_decode64(payload_b64)
    JSON.parse(payload_json)
  rescue => e
    Rails.logger.warn("CustomSSO: failed to decode JWT payload: #{e.message}")
    {}
  end

  def fetch_user_info(access_token, user_info_url)
    uri = URI.parse(user_info_url)
    is_ssl = (uri.scheme == "https")

    Rails.logger.info("CustomSSO: fetching user info from #{user_info_url} (ssl=#{is_ssl})")

    response = Net::HTTP.start(uri.host, uri.port, use_ssl: is_ssl, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      request = Net::HTTP::Get.new(uri.request_uri)
      request["Authorization"] = "Bearer #{access_token}"
      request["Accept"]        = "application/json"
      http.request(request)
    end

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
  def complete_profile_html(username, name, email, error_msg = nil, token = nil)
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
            background: var(--secondary, #f5f6f7);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
          }
          .d-form-container {
            background: var(--secondary, #ffffff);
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 2em;
            width: 100%;
            max-width: 500px;
          }
          .d-form-container h2 {
            text-align: center;
            margin-bottom: 0.5em;
            color: var(--primary, #222222);
            font-size: 1.5em;
            font-weight: 600;
          }
          .d-form-container .subtitle {
            text-align: center;
            color: var(--primary-medium, #666666);
            font-size: 0.875em;
            margin-bottom: 1.5em;
          }
          .d-form {
            margin-top: 1.5em;
          }
          .d-form .form-group {
            margin-bottom: 1.25em;
          }
          .d-form .control-label {
            display: block;
            font-size: 0.875em;
            color: var(--primary, #222222);
            margin-bottom: 0.5em;
            font-weight: 500;
          }
          .d-form .form-control {
            width: 100%;
            padding: 0.75em;
            border: 1px solid var(--primary-low, #e0e0e0);
            border-radius: 4px;
            font-size: 1em;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
            background: var(--secondary, #ffffff);
            color: var(--primary, #222222);
          }
          .d-form .form-control:focus {
            border-color: var(--tertiary, #0e72ed);
            box-shadow: 0 0 0 2px rgba(14, 114, 237, 0.1);
          }
          .d-form .form-control[readonly] {
            background: var(--primary-very-low, #f5f5f5);
            color: var(--primary-medium, #666666);
            cursor: not-allowed;
          }
          .d-form .alert {
            background: var(--danger-low, #ffe6e6);
            color: var(--danger, #e45735);
            border: 1px solid var(--danger-low-mid, #ffcccc);
            border-radius: 4px;
            padding: 0.75em;
            font-size: 0.875em;
            margin-bottom: 1.25em;
          }
          .d-form .btn {
            width: 100%;
            padding: 0.75em 1em;
            font-size: 1em;
            font-weight: 500;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.2s, opacity 0.2s;
            text-align: center;
            display: inline-block;
            line-height: 1.5;
          }
          .d-form .btn-primary {
            background: var(--tertiary, #0e72ed);
            color: var(--secondary, #ffffff);
          }
          .d-form .btn-primary:hover {
            background: var(--tertiary-hover, #0c5fc7);
          }
          .d-form .btn-primary:active {
            background: var(--tertiary-low, #0a4fa0);
          }
          .d-form .form-hint {
            text-align: center;
            margin-top: 1em;
            font-size: 0.8125em;
            color: var(--primary-medium, #666666);
          }
          .required {
            color: var(--danger, #e45735);
          }
        </style>
      </head>
      <body>
        <div class="d-form-container">
          <h2>完善账户信息</h2>
          <p class="subtitle">首次通过统一身份认证登录，请补全以下信息</p>

          <form method="POST" action="#{base_url}/custom-sso/create-account" class="d-form">
            #{token ? "<input type=\"hidden\" name=\"token\" value=\"#{ERB::Util.html_escape(token)}\" />" : ""}
            
            #{error_msg ? "<div class=\"alert\">#{ERB::Util.html_escape(error_msg)}</div>" : ""}

            <div class="form-group">
              <label class="control-label">用户名</label>
              <input type="text" class="form-control" value="#{ERB::Util.html_escape(username)}" 
                     readonly />
              <input type="hidden" name="username" value="#{ERB::Util.html_escape(username)}" />
            </div>

            <div class="form-group">
              <label class="control-label">邮箱 <span class="required">*</span></label>
              <input type="email" name="email" class="form-control" value="#{ERB::Util.html_escape(email)}"
                     placeholder="请输入您的邮箱地址" required />
            </div>

            <div class="form-group">
              <label class="control-label">设置密码 <span class="required">*</span></label>
              <input type="password" name="password" class="form-control" placeholder="至少 8 位" minlength="8" required />
            </div>

            <button type="submit" class="btn btn-primary">完成注册并登录</button>
          </form>

          <p class="form-hint">密码用于后续直接登录 Discourse（也可以始终使用统一身份认证登录）</p>
        </div>
      </body>
      </html>
    HTML
  end
end
