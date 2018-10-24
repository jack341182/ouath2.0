package com.zc.auth.config;


import com.zc.auth.IntegrationTokenEnhancer;
import com.zc.auth.TokenService;
import com.zc.service.UserService;
import org.eclipse.jdt.internal.compiler.lookup.SourceTypeBinding;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.util.SocketUtils;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

/**
 * @Auther: vicykie
 * @Date: 2018/8/22 21:18
 * @Description:
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private UserService userDetailsService;
    /**
     * token增强配置
     */
    @Autowired
    IntegrationTokenEnhancer enhancer;

    @Bean
    public TokenStore tokenStore(DataSource dataSource) {
        return new JdbcTokenStore(dataSource);
    }

    @Bean
    @Scope(scopeName = ConfigurableBeanFactory.SCOPE_SINGLETON)
    @Qualifier("bCryptPasswordEncoder")
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String mobileEncode = encoder.encode("mobile");
        System.out.println(mobileEncode);
        if(!encoder.matches("unity", "$2a$10$QQTKDdNfj9sPjak6c8oWaumvTsa10MxOBOV6BW3DvLWU6VrjDfDam")) {
            System.out.println("失败！");
        } else {
            System.out.println("成功！");
        }

    }

    @Bean
    @Primary
    public AuthorizationServerTokenServices tokenServices(){
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> enhancers = new ArrayList<TokenEnhancer>();
//        enhancers.add(jwtAccessTokenConverter());
        enhancers.add(enhancer);
        enhancerChain.setTokenEnhancers(enhancers);
        TokenService integrationTokenService = new TokenService();
        integrationTokenService.setTokenStore(tokenStore(dataSource));
        integrationTokenService.setAuthenticationManager(authenticationManager);
        integrationTokenService.setTokenEnhancer(enhancerChain);
        integrationTokenService.setAlwaysNewAccessToken(true);
        integrationTokenService.setSupportRefreshToken(true);
        return integrationTokenService;
    }

    /**
     * 用来配置授权（authorization）以及令牌（token）的访问端点和令牌服务(token services)
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //拿到增强器链
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> enhancers = new ArrayList<TokenEnhancer>();
//        enhancers.add(jwtAccessTokenConverter());
        enhancers.add(enhancer);
        enhancerChain.setTokenEnhancers(enhancers);

        endpoints.tokenStore(tokenStore(dataSource))
                .tokenServices(tokenServices())
                .userDetailsService(userDetailsService).tokenEnhancer(enhancerChain)
                .authenticationManager(authenticationManager);

    }


    /**
     * 用来配置令牌端点(Token Endpoint)的安全约束
     *
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }
    @Bean
    public ClientDetailsService clientDetailsService(){
        return new JdbcClientDetailsService(dataSource);
    }


    /**
     * 用来配置客户端详情服务
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService());
    }
}
