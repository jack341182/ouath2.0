package com.auth.provider.config.provider;

import com.kybb.common.cloud.integration.IntegrationUser;
import com.kybb.common.cloud.token.WechatAuthenticationToken;
import com.kybb.libra.service.IntegrationUserDetailService;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Getter
@Slf4j
@Setter
public class WechatLoginAuthenticationProvider extends AbstractIntegrationAuthenticationProvider {
    private PasswordEncoder passwordEncoder;

    private IntegrationUserDetailService userDetailsService;

    private MessageSource springSecurityMessageSource;
    /**
     * The password used to perform
     * {@link PasswordEncoder#matches(CharSequence, String)} on when the user is
     * not found to avoid SEC-2056. This is necessary, because some
     * {@link PasswordEncoder} implementations will short circuit if the password is not
     * in a valid format.
     */
    private volatile String userNotFoundEncodedPassword;
    @Override
    protected void additionalAuthenticationChecks(IntegrationUser userDetails, AbstractAuthenticationToken authentication) throws AuthenticationException {

    }


    @Override
    public void setMessageSource(MessageSource messageSource) {

    }


    /**
     * 告诉AuthenticationManager，如果是WechatAuthenticationToken的话用这个类处理
     */
    @Override
    public boolean supports(Class<?> authentication) {
        //判断传进来的authentication是不是SmsCodeAuthenticationToken类型的
        return WechatAuthenticationToken.class.isAssignableFrom(authentication);
    }


    /**
     * 获取用户信息
     *
     * @param username
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    protected IntegrationUser retrieveUser(String username, AbstractAuthenticationToken authenticationToken) throws AuthenticationException {

        prepareTimingAttackProtection();
        try {
            IntegrationUser loadedUser = this.getUserDetailsService().loadUserByUsername(username);
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }
            return loadedUser;
        } catch (UsernameNotFoundException ex) {
            mitigateAgainstTimingAttack(authenticationToken);
            throw ex;
        } catch (InternalAuthenticationServiceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";

    private void prepareTimingAttackProtection() {
        if (this.userNotFoundEncodedPassword == null) {
            this.userNotFoundEncodedPassword = this.passwordEncoder.encode(USER_NOT_FOUND_PASSWORD);
        }
    }

    private void mitigateAgainstTimingAttack(AbstractAuthenticationToken authentication) {
        if (authentication.getCredentials() != null) {
            String presentedPassword = authentication.getCredentials().toString();
            this.passwordEncoder.matches(presentedPassword, this.userNotFoundEncodedPassword);
        }
    }
}
