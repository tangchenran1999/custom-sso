# frozen_string_literal: true

# 注意：类名必须是 CustomSsoController（顶层命名空间），
# 这样 Rails 路由 "custom_sso#login" 才能正确匹配到这个控制器。
class CustomSsoController < ::ApplicationController
  requires_plugin "custom-sso"

  require "net/http"
  require "json"
  require "openssl"
  require "uri"

  skip_before_action :verify_authenticity_token
  skip_before_action :check_xhr
  skip_before_action :redirect_to_login_if_required

  #
  # 1️⃣ 点击「统一身份认证」后进这里
  #    第三方 SSO 配置的登录入口就是这个地址：/custom-sso/login
  #
  def login
    state = SecureRandom.hex(16)
    session[:custom_sso_nonce] = state

    # 只允许站内相对路径，防止开放重定向（例如 https://evil.com）
    return_url = params[:return_url].to_s
    if return_url.present?
      begin
        uri = URI.parse(return_url)
      rescue URI::InvalidURIError
        uri = nil
      end

      if uri && uri.scheme.nil? && uri.host.nil? && return_url.start_with?("/") && !return_url.start_with?("//")
        session[:custom_sso_return_url] = return_url
      else
        session[:custom_sso_return_url] = "/"
      end
    else
      session[:custom_sso_return_url] = "/"
    end

    # ── 构造 OAuth 2.0 授权请求 ──────────────────────────
    authorize_url = SiteSetting.custom_sso_authorize_url.to_s
    client_id     = SiteSetting.custom_sso_client_id.to_s
    callback_url  = "#{discourse_base}/custom-sso/callback"

    if authorize_url.blank?
      Rails.logger.error("CustomSSO: custom_sso_authorize_url is blank! Please configure it in admin settings.")
      render plain: "OAuth 授权端点未配置，请在后台设置 custom_sso_authorize_url", status: 500
      return
    end

    if client_id.blank?
      Rails.logger.error("CustomSSO: custom_sso_client_id is blank!")
      render plain: "OAuth client_id 未配置，请在后台设置 custom_sso_client_id", status: 500
      return
    end

    # 标准 OAuth 2.0 Authorization Code 请求
    sep = authorize_url.include?("?") ? "&" : "?"
    full_redirect_url = "#{authorize_url}#{sep}" \
      "response_type=code" \
      "&client_id=#{CGI.escape(client_id)}" \
      "&scope=#{CGI.escape('openid profile')}" \
      "&redirect_uri=#{CGI.escape(callback_url)}" \
      "&state=#{state}"

    Rails.logger.info("CustomSSO: login action - redirecting to OAuth authorize: #{full_redirect_url}")

    redirect_to full_redirect_url, allow_other_host: true
  end

  #
  # 2️⃣ 统一认证中心登录成功后回调这里
  #    第三方 SSO 配置的回调地址（redirect_uri）：/custom-sso/callback
  #
  def callback
    code = params[:code]
    state = params[:state]
    idp_token = params[:token].presence

    Rails.logger.info(
      "CustomSSO: Callback received - code=#{code.present? ? 'present' : 'missing'}, token=#{idp_token.present?}, state=#{state}, all_params=#{params.except(:controller, :action).inspect}"
    )

    # ── 门户"进入系统"兜底 ──────────────────────────────
    # 门户的 /launch 接口只返回 launchUrl（不带任何参数），
    # 浏览器直接 GET /custom-sso/callback 时没有 code / token / email。
    # 此时自动重定向到 /custom-sso/login，走完整的 SSO 流程。
    if code.blank? && idp_token.blank? && params[:email].blank? && params[:username].blank? && params[:account].blank?
      Rails.logger.info("CustomSSO: Callback received without any auth params — redirecting to /custom-sso/login")
      redirect_to "/custom-sso/login"
      return
    end

    stored_nonce = session[:custom_sso_nonce]
    if stored_nonce.present?
      if state != stored_nonce
        Rails.logger.error("CustomSSO: State mismatch - expected #{stored_nonce}, got #{state}")
        raise Discourse::InvalidAccess, "State 验证失败"
      end
    else
      Rails.logger.info("CustomSSO: No stored nonce; allowing IdP/Portal initiated callback without state binding")
    end

    # 1) 先尝试从 token 解出用户信息（兼容门户直接带 token 回跳）
    email = nil
    username = nil
    name = nil
    if idp_token.present?
      begin
        decoded = decode_idp_token(idp_token)
        email ||= decoded[:email] || decoded['email']
        username ||= decoded[:username] || decoded['username'] || decoded[:account] || decoded['account'] || decoded[:login] || decoded['login']
        name ||= decoded[:name] || decoded['name'] || decoded[:display_name] || decoded['display_name'] || username
      rescue => e
        Rails.logger.error("CustomSSO: Failed to decode idp token in callback: #{e.class} #{e.message}")
        # 不中断，让后续 code 流程继续
      end
    end

    # 2) 如果回调直接带了用户字段，也尝试读取
    email ||= params[:email]
    username ||= params[:username] || params[:account] || params[:login]
    name ||= params[:name] || params[:display_name] || username

    # 3) 如果还缺，就走 OAuth code 换取用户信息
    if (email.blank? || username.blank?)
      if code.blank?
        Rails.logger.error("CustomSSO: Missing authorization code and no usable token/params for user info")
        raise Discourse::InvalidAccess, "缺少授权码且无法获取用户信息"
      end

      token_url = SiteSetting.custom_sso_token_url.to_s
      user_info_url = SiteSetting.custom_sso_user_info_url.to_s

      if token_url.present? && user_info_url.present?
        # OAuth 标准流程：code -> token -> user_info
        begin
          access_token = exchange_code_for_token(code, token_url)
          user_info = fetch_user_info(access_token, user_info_url)

          email = user_info[:email] || user_info["email"]
          username = user_info[:username] || user_info["username"] ||
            user_info[:account] || user_info["account"] ||
            user_info[:login] || user_info["login"]
          name = user_info[:name] || user_info["name"] ||
            user_info[:display_name] || user_info["display_name"] ||
            username
        rescue => e
          Rails.logger.error("CustomSSO: Failed to exchange code for user info: #{e.message}")
          Rails.logger.error(e.backtrace.join("\n"))
          raise Discourse::InvalidAccess, "获取用户信息失败: #{e.message}"
        end
      else
        # 如果配置了 token_url 但没有配置 user_info_url，或者反过来
        if token_url.present? || user_info_url.present?
          Rails.logger.error("CustomSSO: Token URL or User Info URL is configured but not both")
          raise Discourse::InvalidAccess, "OAuth 配置不完整，请同时配置 token_url 和 user_info_url"
        end

        # 如果都没有配置，说明统一认证中心应该直接返回用户信息
        Rails.logger.error("CustomSSO: Cannot extract user info from callback params and no OAuth endpoints configured")
        Rails.logger.error("CustomSSO: Available params: #{params.except(:controller, :action).keys.join(', ')}")
        raise Discourse::InvalidAccess, "无法获取用户信息。请检查：1) 统一认证中心是否在回调中返回 email/username 参数，或 2) 是否配置了 OAuth token 和 user_info 端点"
      end
    end

    if email.blank? || username.blank?
      Rails.logger.error("CustomSSO: Missing email or username after extraction")
      raise Discourse::InvalidAccess, "缺少用户邮箱或用户名"
    end

    # 3. 查找或创建用户（同用户名/邮箱就复用；没有则注册）
    user = find_or_provision_user(email: email, username: username, name: name)

    # 4. 登录并跳转
    log_on_user(user)
    return_url = session[:custom_sso_return_url] || "/"
    session.delete(:custom_sso_nonce)
    session.delete(:custom_sso_return_url)
    redirect_to return_url
  end

  # 3️⃣ IdP 发起（门户直接带 token 打开 Discourse）
  # 门户生成 HS256 JWT，包含 email / username / name，可选 exp、iat、iss
  def idp_initiated
    unless SiteSetting.custom_sso_idp_initiated_enabled
      raise Discourse::InvalidAccess
    end

    token = params[:token].to_s.presence
    raise Discourse::InvalidAccess, "缺少 token" if token.blank?

    secret = SiteSetting.custom_sso_idp_jwt_secret.to_s.presence
    issuer = SiteSetting.custom_sso_idp_issuer.to_s.presence
    raise Discourse::InvalidAccess, "未配置 JWT 密钥" if secret.blank?

    begin
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
    rescue => e
      Rails.logger.error("CustomSSO: idp_initiated token decode failed: #{e.class} #{e.message}")
      raise Discourse::InvalidAccess, "token 验证失败"
    end

    email = decoded["email"] || decoded[:email]
    username = decoded["username"] || decoded[:username] || decoded["account"] || decoded[:account] || decoded["login"] || decoded[:login]
    name = decoded["name"] || decoded[:name] || decoded["display_name"] || decoded[:display_name] || username

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

  # 用 code 换取 access_token
  def exchange_code_for_token(code, token_url)
    callback_url = "#{discourse_base}/custom-sso/callback"
    client_id = SiteSetting.custom_sso_client_id.to_s
    client_secret = SiteSetting.custom_sso_client_secret.to_s

    uri = URI.parse(token_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl # 开发环境可以跳过证书验证

    request = Net::HTTP::Post.new(uri.request_uri)
    request.set_form_data(
      grant_type: "authorization_code",
      code: code,
      redirect_uri: callback_url,
      client_id: client_id,
      client_secret: client_secret
    )

    response = http.request(request)

    unless response.is_a?(Net::HTTPSuccess)
      Rails.logger.error("CustomSSO: Token exchange failed - #{response.code} #{response.message}")
      Rails.logger.error("CustomSSO: Response body: #{response.body}")
      raise "Token 交换失败: #{response.code} #{response.message}"
    end

    result = JSON.parse(response.body)
    access_token = result["access_token"] || result[:access_token]

    if access_token.blank?
      Rails.logger.error("CustomSSO: No access_token in token response: #{result.inspect}")
      raise "Token 响应中缺少 access_token"
    end

    Rails.logger.info("CustomSSO: Successfully exchanged code for token")
    access_token
  rescue JSON::ParserError => e
    Rails.logger.error("CustomSSO: Failed to parse token response: #{e.message}")
    raise "Token 响应解析失败: #{e.message}"
  end

  # 用 access_token 获取用户信息
  def fetch_user_info(access_token, user_info_url)
    uri = URI.parse(user_info_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl

    request = Net::HTTP::Get.new(uri.request_uri)
    request["Authorization"] = "Bearer #{access_token}"
    request["Accept"] = "application/json"

    response = http.request(request)

    unless response.is_a?(Net::HTTPSuccess)
      Rails.logger.error("CustomSSO: User info fetch failed - #{response.code} #{response.message}")
      Rails.logger.error("CustomSSO: Response body: #{response.body}")
      raise "获取用户信息失败: #{response.code} #{response.message}"
    end

    result = JSON.parse(response.body)
    Rails.logger.info("CustomSSO: Successfully fetched user info: #{result.inspect}")
    result
  rescue JSON::ParserError => e
    Rails.logger.error("CustomSSO: Failed to parse user info response: #{e.message}")
    raise "用户信息响应解析失败: #{e.message}"
  end

  def find_or_provision_user(email:, username:, name:)
    normalized_username = normalize_username(username)
    normalized_email = email.to_s.strip.downcase

    # 优先按用户名匹配（符合你"用户名相同就用已有的"诉求），其次按邮箱兜底
    user = User.find_by(username: normalized_username) || User.find_by(email: normalized_email)
    if user
      # 尝试把基础信息同步一下（不强制，避免撞邮箱）
      begin
        if name.present? && user.name.to_s != name.to_s
          user.name = name.to_s
        end

        if normalized_email.present? &&
             user.email.to_s.downcase != normalized_email &&
             !User.exists?(email: normalized_email)
          user.email = normalized_email
        end

        user.save! if user.changed?
      rescue => e
        Rails.logger.warn("CustomSSO: Failed to sync user base fields: user_id=#{user.id}, err=#{e.class}: #{e.message}")
      end

      Rails.logger.info("CustomSSO: Found existing user - user_id=#{user.id}, email=#{normalized_email}, username=#{normalized_username}")
      return user
    end

    final_username = ensure_unique_username(normalized_username)
    password = SecureRandom.hex(32)

    user = User.create!(
      email: normalized_email,
      username: final_username,
      name: name.present? ? name.to_s : final_username,
      password: password,
      password_confirmation: password,
      active: true,
      approved: true
    )

    Rails.logger.info("CustomSSO: Created new user - user_id=#{user.id}, email=#{normalized_email}, username=#{final_username}")
    user
  end

  def normalize_username(username)
    u = username.to_s.strip
    u = u.gsub(/\s+/, "_")
    u = u.gsub(/[^A-Za-z0-9_\.]/, "_")
    u = u[0, 60] # Discourse 默认用户名最长 60
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
