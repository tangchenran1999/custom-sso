package com.databuff.manage.controller;

import com.databuff.manage.config.common.CommonResponse;
import com.databuff.manage.config.exception.CustomException;
import com.databuff.manage.model.dto.PortalAppDTO;
import com.databuff.manage.model.dto.PortalLaunchDTO;
import com.databuff.manage.service.PortalService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Api(tags = "应用门户")
@RestController
@RequestMapping("/portal")
public class PortalController {
    private final PortalService portalService;

    public PortalController(PortalService portalService) {
        this.portalService = portalService;
    }

    @ApiOperation("查询当前用户可见应用列表")
    @GetMapping("/apps")
    public CommonResponse<List<PortalAppDTO>> listApps(
            @RequestParam(name = "keyword", required = false) String keyword,
            @RequestParam(name = "category", required = false) String category,
            @RequestParam(name = "onlyFavorite", required = false) Boolean onlyFavorite) {
        CurrentUser currentUser = currentUser();
        List<PortalAppDTO> apps = portalService.listApps(currentUser.userId, currentUser.account, keyword, category,
                onlyFavorite);
        return new CommonResponse<>(200, "SUCCESS", apps);
    }

    @ApiOperation("查询当前用户最近访问应用")
    @GetMapping("/recent")
    public CommonResponse<List<PortalAppDTO>> listRecentApps(
            @RequestParam(name = "limit", required = false) Integer limit) {
        CurrentUser currentUser = currentUser();
        List<PortalAppDTO> apps = portalService.listRecentApps(currentUser.userId, currentUser.account, limit);
        return new CommonResponse<>(200, "SUCCESS", apps);
    }

    @ApiOperation("生成门户应用跳转地址")
    @PostMapping("/apps/{clientId}/launch")
    public CommonResponse<PortalLaunchDTO> launch(
            @PathVariable("clientId") String clientId,
            HttpServletRequest request) {
        CurrentUser currentUser = currentUser();
        PortalLaunchDTO dto = portalService.buildLaunchUrl(currentUser.userId, currentUser.account, clientId,
                getRequestIp(request), request == null ? null : request.getHeader("User-Agent"));
        return new CommonResponse<>(200, "SUCCESS", dto);
    }

    @ApiOperation("收藏应用")
    @PostMapping("/apps/{clientId}/favorite")
    public CommonResponse<String> addFavorite(@PathVariable("clientId") String clientId) {
        CurrentUser currentUser = currentUser();
        portalService.addFavorite(currentUser.userId, currentUser.account, clientId);
        return new CommonResponse<>(200, "SUCCESS", "收藏成功");
    }

    @ApiOperation("取消收藏")
    @DeleteMapping("/apps/{clientId}/favorite")
    public CommonResponse<String> removeFavorite(@PathVariable("clientId") String clientId) {
        CurrentUser currentUser = currentUser();
        portalService.removeFavorite(currentUser.userId, currentUser.account, clientId);
        return new CommonResponse<>(200, "SUCCESS", "取消收藏成功");
    }

    private CurrentUser currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new CustomException("未登录");
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof org.springframework.security.oauth2.jwt.Jwt) {
            org.springframework.security.oauth2.jwt.Jwt jwt = (org.springframework.security.oauth2.jwt.Jwt) principal;
            Object userIdObj = jwt.getClaims().get("userId");
            String account = jwt.getClaimAsString("account");
            Integer userId = castUserId(userIdObj);
            if (userId == null || account == null || account.isBlank()) {
                throw new CustomException("登录信息无效");
            }
            return new CurrentUser(userId, account);
        }

        if (principal instanceof com.databuff.manage.config.security.IdpUserPrincipal) {
            com.databuff.manage.config.security.IdpUserPrincipal p = (com.databuff.manage.config.security.IdpUserPrincipal) principal;
            if (p.getUser() == null || p.getUser().getId() == null) {
                throw new CustomException("登录信息无效");
            }
            return new CurrentUser(p.getUser().getId(), p.getUser().getAccount());
        }

        throw new CustomException("未登录");
    }

    private Integer castUserId(Object userIdObj) {
        if (userIdObj instanceof Integer) {
            return (Integer) userIdObj;
        }
        if (userIdObj instanceof Long) {
            return ((Long) userIdObj).intValue();
        }
        return null;
    }

    private String getRequestIp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static class CurrentUser {
        private final Integer userId;
        private final String account;

        private CurrentUser(Integer userId, String account) {
            this.userId = userId;
            this.account = account;
        }
    }
}

