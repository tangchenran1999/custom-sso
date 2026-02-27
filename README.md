# custom_sso（对接统一认证平台的自动登录/自动注册）

这个插件用于把外部统一认证平台（OAuth2/OIDC 授权码模式）接入 Discourse，实现：

- **从统一认证平台跳转到 Discourse 时自动登录**
- **Discourse 中已存在同用户名则直接登录；不存在则自动注册并登录**

## 你现在的目标流程（对应你给的 Java `/launch`）

统一认证平台点击按钮 → 调用 Java `/portal/apps/{clientId}/launch` → 得到 `launchUrl`（本质是授权端 `/oauth2/authorize`）→ 浏览器跳转授权端 → 授权端回跳到 Discourse：

- **Discourse 回调地址**：`{DISCOURSE_BASE_URL}/custom-sso/callback`
- 回调参数通常是：`code`、`state`（以及可能直接带 `email/username`）

插件会在 `callback` 中：

- 通过 `code` 去换 `access_token`（`custom_sso_token_url`）
- 用 `access_token` 拉用户信息（`custom_sso_user_info_url`）
- 按 **用户名优先** 查找用户；没有则 **自动注册**；最后 `log_on_user`

## Portal（Java）侧需要怎么配

在你 Java 侧（见 `PortalServiceImpl#buildAuthorizeUrl`）里，给 Discourse 这个应用配置的 `redirect_uri` 必须是：

- `https://你的-discourse-域名/custom_sso/callback`

并且把这个地址加入该 `clientId` 的 **redirectUri 白名单**（你 Java 代码里叫 `registeredRedirectUris`）。

## Discourse（插件）侧需要怎么配（Site Settings）

在 Discourse 后台：`Admin -> Settings -> Plugins -> custom_sso` 配置：

- **custom_sso_token_url**：授权码换 token 的端点（例如 `https://统一认证平台/oauth2/token`）
- **custom_sso_user_info_url**：用 token 拉用户信息的端点（例如 `https://统一认证平台/oauth2/userinfo` 或你们的用户信息 API）
- **custom_sso_client_id / custom_sso_client_secret**：如果 token 端点要求 client 认证，就填写

说明：

- `custom_sso_idp_login_url` 只影响 Discourse 登录页里那颗“统一身份认证”按钮（走 `/custom_sso/login`）。如果你们完全从 Portal 进入 Discourse，也可以不管它。

## 用户信息字段约定

插件会从回调/用户信息接口里优先取这些字段：

- **用户名**：`username` / `account` / `login`
- **邮箱**：`email`（必需）
- **显示名**：`name` / `display_name`

只要能拿到 `email + username`，就能自动登录/注册。

