package com.auth.provider.config.filter;

import com.auth.provider.config.properties.WechatProperties;
import com.auth.provider.constants.AuthorizationServerConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import static com.auth.provider.constants.AuthorizationServerConstants.WECHAT_LOGIN_URL;


/**
 * 模仿UsernamePasswordAuthenticationFilter 写的短信验证码过滤器
 * ClassName: SmsCodeAuthenticationFilter
 */
@Slf4j
public class WechatAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final WechatProperties wechatProperties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();


    private boolean postOnly = true;//只处理post请求


    public WechatAuthenticationFilter(WechatProperties wechatProperties) {
        //过滤的请求url，登录表单的url
        super(new AntPathRequestMatcher(WECHAT_LOGIN_URL, "POST"));
        this.wechatProperties = wechatProperties;

    }

    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        //获取 wxLoginCode
        String wxLoginCode = obtainWxLoginCode(request);

        log.info("login code ====" + wxLoginCode);
        // TODO: 2018/9/6  获取openid
        String header = request.getHeader("Authorization");
        /**
         * 构造OAuth2Request 第一步，从请求头获取clientId
         */
        //base64解码获取clientId、clientSecret
        String[] tokens = HttpUtil.extractAndDecodeHeader(header, request);
        assert tokens.length == 2;
        String clientId = tokens[0];
        String openId = this.getOpenId(clientId, wxLoginCode);
        if (StringUtils.isEmpty(openId)) {
            HttpUtil.writeResponse(objectMapper, "非法请求", response, HttpStatus.NOT_ACCEPTABLE);
            return null;
        }
        //到这里认证还没通过，SmsCodeAuthenticationToken一个参数的构造，是没有认证通过的
        WechatAuthenticationToken authRequest = new WechatAuthenticationToken(
                AuthorizationServerConstants.WECHAT_PREFIX + openId.trim());
        //把请求里一些信息如ip等set给SmsCodeAuthenticationToken，此时SmsCodeAuthenticationToken还没认证
        setDetails(request, authRequest);

        /**
         * 认证，在这里把SmsCodeAuthenticationToken交给AuthenticationManager，
         * 找到SmsCodeAuthenticationProvider，调用其authenticate()方法认证
         */
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    private String getOpenId(String clientId, String wxLoginCode) {
        if (clientId.equalsIgnoreCase("trucker")) {
            Map<String, Object> params = new HashMap<>();
            params.put("appid", wechatProperties.getTrucker().getAppId());
            params.put("secret", wechatProperties.getTrucker().getAppSecret());
            params.put("js_code", wxLoginCode);
            params.put("grant_type", "authorization_code");
            String forObject = restTemplate.getForObject(wechatProperties.getGetOpenIdUrl(), String.class, params);
            JSONObject jsonObject = JSONObject.parseObject(forObject);
            log.info(jsonObject.toJSONString());
            return jsonObject.getString("openid");
        }
        return null;
    }

    /**
     * 获取手机号
     */
    private String obtainWxLoginCode(HttpServletRequest request) {
        return request.getParameter(AuthorizationServerConstants.WECHAT_LOGIN_URL_PARAME);
    }

    /**
     * Provided so that subclasses may configure what is put into the authentication
     * request's details property.
     *
     * @param request     that an authentication request is being created for
     * @param authRequest the authentication request object that should have its details
     *                    set
     */
    protected void setDetails(HttpServletRequest request,
                              WechatAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }


    /**
     * Defines whether only HTTP POST requests will be allowed by this filter. If set to
     * true, and an authentication request is received which is not a POST request, an
     * exception will be raised immediately and authentication will not be attempted. The
     * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
     * authentication.
     * <p>
     * Defaults to <tt>true</tt> but may be overridden by subclasses.
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }


}
