package com.auth.provider.config.handler;

import com.auth.common.HttpUtil;
import com.auth.common.IntegrationUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.MapUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 认证成功后做的处理
 * ClassName: LibraAuthenticationSuccessHandler
 */
//@Component
//@Slf4j
//public class LibraAuthenticationSuccessHandler
//        //spring默认的登录成功处理器，实现了AuthenticationSuccessHandler接口，适配登录后 重定向和返回json两种用这个实现
//        extends SavedRequestAwareAuthenticationSuccessHandler
//        //返回json用这个实现
//        /*implements AuthenticationSuccessHandler*/ {
//
//    @Autowired
//    ObjectMapper objectMapper;
//
//    @Autowired
//    private ClientDetailsService clientDetailsService;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Autowired
//    private AuthorizationServerTokenServices authorizationServerTokenServices;
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//                                        Authentication authentication) throws IOException, ServletException {
//        if (log.isDebugEnabled()) {
//            log.debug("=====================登录成功=========================");
//        }
//        //获取请求头里Authorization信息
//        String header = request.getHeader("Authorization");
//        /**
//         * 构造OAuth2Request 第一步，从请求头获取clientId
//         */
//        //base64解码获取clientId、clientSecret
//        String[] tokens = HttpUtil.extractAndDecodeHeader(header, request);
//        assert tokens.length == 2;
//        String clientId = tokens[0];
//        String clientSecret = tokens[1];
//        response.setContentType("application/json;charset=UTF-8");
//        /**
//         * 构造OAuth2Request 第二步，根据clientId 获取ClientDetails对象
//         */
//        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//        if (clientDetails == null) {
//            throw new UnapprovedClientAuthenticationException("clientId对应的配置信息不存在，clientId:" + clientId);
//        } else if (!passwordEncoder.matches(clientSecret, clientDetails.getClientSecret())) {
//            throw new UnapprovedClientAuthenticationException("clientSecret不匹配，clientId:" + clientId);
//        }
//
//        /**
//         * 构造OAuth2Request 第三步，new TokenRequest
//         * 第一个参数是个map，放的是每个授权模式特有的参数，spring-security会根据这些参数构建Authentication
//         * 我们这里已获取到了Authentication，弄个空的map就可
//         */
//        TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_SORTED_MAP, clientId, clientDetails.getScope(), "custom");
//        /**
//         * 构造OAuth2Request 第四步，创建 OAuth2Request
//         */
//        OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//        /**
//         * 构造OAuth2Request 第五步，创建 OAuth2Authentication
//         */
//        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);
//        /**
//         * 构造OAuth2Request 第六步，authorizationServerTokenServices创建 OAuth2AccessToken
//         */
//        OAuth2AccessToken accessToken = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);
//        IntegrationUser principal = (IntegrationUser) oAuth2Authentication.getPrincipal();
//        if (log.isDebugEnabled()) {
//            log.debug("======> principal is " + principal.toString()+" <=======");
//            log.debug(" 生成的===> access_token is " + accessToken.toString());
//        }
//        response.getWriter().write(objectMapper.writeValueAsString(accessToken));
//        response.flushBuffer();
//    }
//
//
//}
