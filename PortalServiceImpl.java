package com.databuff.manage.service.impl;

import com.databuff.manage.config.exception.CustomException;
import com.databuff.manage.mapper.PortalMapper;
import com.databuff.manage.mapper.RoleMapper;
import com.databuff.manage.model.dto.PortalAppDTO;
import com.databuff.manage.model.dto.PortalLaunchDTO;
import com.databuff.manage.model.saas.PortalLaunchConfig;
import com.databuff.manage.service.PortalService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
public class PortalServiceImpl implements PortalService {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String OPEN_MODE_NEW_TAB = "NEW_TAB";
    private static final String OPEN_MODE_SAME_TAB = "SAME_TAB";

    private final PortalMapper portalMapper;
    private final RoleMapper roleMapper;

    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String issuer;

    public PortalServiceImpl(PortalMapper portalMapper, RoleMapper roleMapper) {
        this.portalMapper = portalMapper;
        this.roleMapper = roleMapper;
    }

    @Override
    public List<PortalAppDTO> listApps(Integer userId, String account, String keyword, String category, Boolean onlyFavorite) {
        validateUser(userId, account);
        return portalMapper.listVisibleApps(userId, account, getRoleCodes(userId),
                StringUtils.trimToEmpty(keyword),
                StringUtils.trimToEmpty(category),
                onlyFavorite);
    }

    @Override
    public List<PortalAppDTO> listRecentApps(Integer userId, String account, Integer limit) {
        validateUser(userId, account);
        int safeLimit = (limit == null || limit <= 0) ? 10 : Math.min(limit, 50);
        return portalMapper.listRecentApps(userId, account, getRoleCodes(userId), safeLimit);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public PortalLaunchDTO buildLaunchUrl(Integer userId, String account, String clientId, String ip, String userAgent) {
        validateUser(userId, account);
        if (StringUtils.isBlank(clientId)) {
            throw new CustomException("clientId不能为空");
        }

        String traceId = UUID.randomUUID().toString().replace("-", "");
        String trimmedClientId = clientId.trim();
        try {
            PortalLaunchConfig config = portalMapper.selectLaunchConfigForUser(userId, account, getRoleCodes(userId),
                    trimmedClientId);
            if (config == null) {
                throw new CustomException("应用不存在或无访问权限");
            }

            String redirectUri = resolveRedirectUri(config);
            String state = randomState(24);
            String launchUrl = buildAuthorizeUrl(config.getClientId(), redirectUri, state);

            portalMapper.upsertRecent(userId, config.getClientId());

            safeInsertLaunchAudit(traceId, userId, account, config.getClientId(), launchUrl, "SUCCESS", null, null, ip,
                    userAgent);

            PortalLaunchDTO dto = new PortalLaunchDTO();
            dto.setLaunchUrl(launchUrl);
            dto.setOpenMode(normalizeOpenMode(config.getOpenMode()));
            return dto;
        } catch (CustomException e) {
            safeInsertLaunchAudit(traceId, userId, account, trimmedClientId, null, "FAIL", "PORTAL_LAUNCH_FAILED",
                    e.getMessage(), ip, userAgent);
            throw e;
        } catch (Exception e) {
            safeInsertLaunchAudit(traceId, userId, account, trimmedClientId, null, "FAIL", "PORTAL_LAUNCH_FAILED",
                    e.getMessage(), ip, userAgent);
            log.error("buildLaunchUrl failed, userId={}, account={}, clientId={}", userId, account, trimmedClientId, e);
            throw new CustomException("生成跳转地址失败");
        }
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void addFavorite(Integer userId, String account, String clientId) {
        validateUser(userId, account);
        if (StringUtils.isBlank(clientId)) {
            throw new CustomException("clientId不能为空");
        }
        PortalLaunchConfig config = portalMapper.selectLaunchConfigForUser(userId, account, getRoleCodes(userId),
                clientId.trim());
        if (config == null) {
            throw new CustomException("应用不存在或无访问权限");
        }
        portalMapper.insertFavorite(userId, clientId.trim());
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void removeFavorite(Integer userId, String account, String clientId) {
        validateUser(userId, account);
        if (StringUtils.isBlank(clientId)) {
            throw new CustomException("clientId不能为空");
        }
        portalMapper.deleteFavorite(userId, clientId.trim());
    }

    private List<String> getRoleCodes(Integer userId) {
        List<String> roleCodes = roleMapper.selectRoleCodesByUserId(userId);
        return roleCodes == null ? new ArrayList<>() : roleCodes;
    }

    private void validateUser(Integer userId, String account) {
        if (userId == null || StringUtils.isBlank(account)) {
            throw new CustomException("未登录");
        }
    }

    private String resolveRedirectUri(PortalLaunchConfig config) {
        List<String> registeredUris = parseCsv(config.getRegisteredRedirectUris());
        if (registeredUris.isEmpty()) {
            throw new CustomException("客户端回调地址未配置");
        }
        String selected = StringUtils.trimToNull(config.getLaunchRedirectUri());
        if (selected == null) {
            selected = registeredUris.get(0);
        }
        if (!registeredUris.contains(selected)) {
            throw new CustomException("门户回调地址不在客户端白名单中");
        }
        return selected;
    }

    private List<String> parseCsv(String csv) {
        List<String> values = new ArrayList<>();
        if (StringUtils.isBlank(csv)) {
            return values;
        }
        String[] arr = csv.split(",");
        for (String item : arr) {
            String v = StringUtils.trimToNull(item);
            if (v != null) {
                values.add(v);
            }
        }
        return values;
    }

    private String buildAuthorizeUrl(String clientId, String redirectUri, String state) {
        String issuerBase = StringUtils.removeEnd(StringUtils.trimToEmpty(issuer), "/");
        return UriComponentsBuilder.fromHttpUrl(issuerBase + "/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("scope", "openid profile")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("state", state)
                .build()
                .encode()
                .toUriString();
    }

    private String normalizeOpenMode(String openMode) {
        if (OPEN_MODE_SAME_TAB.equalsIgnoreCase(openMode)) {
            return OPEN_MODE_SAME_TAB;
        }
        return OPEN_MODE_NEW_TAB;
    }

    private String randomState(int len) {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(chars.charAt(SECURE_RANDOM.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private void safeInsertLaunchAudit(String traceId, Integer userId, String account, String clientId, String launchUrl,
            String result, String errorCode, String errorMessage, String ip, String userAgent) {
        try {
            portalMapper.insertLaunchAudit(traceId, userId, account, clientId, launchUrl, result, errorCode, errorMessage,
                    ip, userAgent);
        } catch (Exception e) {
            log.warn("save portal launch audit failed, traceId={}, userId={}, clientId={}", traceId, userId, clientId, e);
        }
    }
}

