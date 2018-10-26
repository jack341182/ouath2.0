package com.auth.provider.service;

import com.kybb.common.cloud.constants.AuthorizationServerConstants;
import com.kybb.common.cloud.integration.IntegrationUser;
import com.kybb.common.cloud.util.HttpUtil;
import com.kybb.common.http.Body;
import com.kybb.libra.feign.UserInfoFeignClient;
import com.kybb.solar.user.enums.ApplicationTypeEnum;
import com.kybb.solar.user.request.AccountRequest;
import com.kybb.solar.user.vo.AccountVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * @Auther: vicykie
 * @Date: 2018/8/22 23:06
 * <p>
 * 读取用户信息
 */
@Component
@Slf4j
public class IntegrationUserDetailService implements UserDetailsService {
    @Autowired
    private UserInfoFeignClient userFeignClient;


    @Autowired
    private HttpServletRequest request;
    //spring工具类
    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Autowired
    private TokenStore tokenStore;


    @Override
    public IntegrationUser loadUserByUsername(String username) throws UsernameNotFoundException {
        if (log.isDebugEnabled()) {
            log.debug(" request is  refresh token ? " + isRefreshTokenRequest(request) + "  ==== 登录用户 ====" + username);
        }
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && isRefreshTokenRequest(request)) {//已经授权
            String refresh_token = request.getParameter("refresh_token");
            OAuth2Authentication oAuth2Authentication = tokenStore.readAuthenticationForRefreshToken(tokenStore.readRefreshToken(refresh_token));
            IntegrationUser principal = (IntegrationUser) oAuth2Authentication.getPrincipal();
            if (log.isDebugEnabled()) {
                log.debug("【before】 refresh token  is " + refresh_token);
            }
            AccountRequest a = new AccountRequest();
            a.setUserId(principal.getId());
            a.setAppType(ApplicationTypeEnum.valueOf(principal.getAppType()));
            principal = getUser(a);//重新获取用户信息。
            OAuth2Authentication auth2Authentication = new OAuth2Authentication(oAuth2Authentication.getOAuth2Request(), new UsernamePasswordAuthenticationToken(principal, authentication.getCredentials(), authentication.getAuthorities()));
//            tokenStore.storeAccessToken(oAuth2RefreshToken);
            context.setAuthentication(auth2Authentication);
            return principal;
        }
        AccountRequest a = new AccountRequest();
        if (username.startsWith(AuthorizationServerConstants.WECHAT_PREFIX)) {
            a.setWxOpenId(username.replace(AuthorizationServerConstants.WECHAT_PREFIX, ""));
        } else if (username.startsWith(AuthorizationServerConstants.SMS_CODE_PREFIX)) {
            a.setTelephone(username.replace(AuthorizationServerConstants.SMS_CODE_PREFIX, ""));
        } else {
            a.setUsername(username);
        }
        String header = request.getHeader("Authorization");
        String[] tokens = HttpUtil.extractAndDecodeHeader(header, request);
        assert tokens.length == 2;
        String clientId = tokens[0];
        a.setAppType(ApplicationTypeEnum.valueOf(clientId));
        return getUser(a);
    }

    private IntegrationUser getUser(AccountRequest accountRequest) {
        ResponseEntity<Body<AccountVO>> responseEntity = userFeignClient.accounts(accountRequest);
        if (log.isDebugEnabled()) {
            log.debug("-=====》 h获取用户信息  accountRequest is " + accountRequest);
        }
        if (responseEntity.getStatusCode() == HttpStatus.OK) {
            AccountVO accountVO = responseEntity.getBody().getData();
            if (Objects.isNull(accountVO)) {
                throw new UsernameNotFoundException("用户不存在");
            }
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(accountVO.getUserType().name()));
            return new IntegrationUser(accountVO.getUsername(), accountVO.getPassword(), accountVO.getEnabled() == null ? true : accountVO.getEnabled(),
                    true, true, true,
                    authorities, accountVO.getId(), accountVO.getWxOpenId(), accountVO.getEmail(), accountVO.getTelephone(), accountVO.getUserType(), null,
                    accountRequest.getAppType().name(), accountVO.getDeleted() == null ? false : accountVO.getDeleted(), accountVO.getRoleIds());
        } else {
            log.error("服务器异常=== user-center-api");
            throw new InternalAuthenticationServiceException("服务异常。user-center-api");
        }

    }

    /**
     * 随机username
     */
    private String generateRandomUsername() {
        //取当前时间的长整形值包含毫秒
        long millis = System.currentTimeMillis();
        //long millis = System.nanoTime();
        //加上三位随机数
        Random random = new Random();
        int end3 = random.nextInt(999);
        //如果不足三位前面补0
        String str = millis + String.format("%03d", end3);
        return str;
    }

    private boolean isRefreshTokenRequest(HttpServletRequest request) {
        return "refresh_token".equals(request.getParameter("grant_type")) && request.getParameter("refresh_token") != null;
    }
}
