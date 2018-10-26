package com.auth.provider.config.provider;

import com.kybb.common.cloud.integration.IntegrationUser;
import com.kybb.libra.auth.IntegrationMessageResourceBundle;
import com.kybb.libra.exception.DeletedException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

@Slf4j
@Setter
@Getter
public abstract class AbstractIntegrationAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {

    /**
     * 获取用户信息
     *
     * @param username
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    protected abstract IntegrationUser retrieveUser(String username, AbstractAuthenticationToken authenticationToken) throws AuthenticationException;

    protected abstract void additionalAuthenticationChecks(IntegrationUser userDetails, AbstractAuthenticationToken authentication) throws AuthenticationException;

    public abstract void setPasswordEncoder(PasswordEncoder passwordEncoder);

    protected MessageSourceAccessor messages = IntegrationMessageResourceBundle.getAccessor();
    private boolean forcePrincipalAsString = false;
    protected boolean hideUserNotFoundExceptions = true;
    private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
    private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();


    public final void afterPropertiesSet() throws Exception {
//        Assert.notNull(this.userCache, "A user cache must be set");
        Assert.notNull(this.messages, "A message source must be set");
        doAfterPropertiesSet();
    }

    protected void doAfterPropertiesSet() throws Exception {
    }


    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        // Determine username
        String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED"
                : authentication.getName();
        IntegrationUser user = retrieveUser(username,
                (AbstractAuthenticationToken) authentication);
        try {
            preAuthenticationChecks.check(user);
            additionalAuthenticationChecks(user,
                    (AbstractAuthenticationToken) authentication);
        } catch (AuthenticationException exception) {
            // There was a problem, so try again after checking
            // we're using latest data (i.e. not from the cache)
//            user = retrieveUser(username,
//                    (AbstractAuthenticationToken) authentication);
//            preAuthenticationChecks.check(user);
//            additionalAuthenticationChecks(user,
//                    (AbstractAuthenticationToken) authentication);
            throw exception;
        }
        postAuthenticationChecks.check(user);
        Object principalToReturn = user;
        if (forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }
        return createSuccessAuthentication(principalToReturn, authentication, user);
    }


    /**
     * Creates a successful {@link Authentication} object.
     * <p>
     * Protected so subclasses can override.
     * </p>
     * <p>
     * Subclasses will usually store the original credentials the user supplied (not
     * salted or encoded passwords) in the returned <code>Authentication</code> object.
     * </p>
     *
     * @param principal      that should be the principal in the returned object (defined by
     * @param authentication that was presented to the provider for validation
     * @param user           that was loaded by the implementation
     * @return the successful authentication token
     */
    protected Authentication createSuccessAuthentication(Object principal,
                                                         Authentication authentication, UserDetails user) {
        // Ensure we return the original credentials the user supplied,
        // so subsequent attempts are successful even with encoded passwords.
        // Also ensure we return the original getDetails(), so that future
        // authentication events after cache expiry contain the details
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                principal, authentication.getCredentials(),
                authoritiesMapper.mapAuthorities(user.getAuthorities()));
        result.setDetails(authentication.getDetails());

        return result;
    }


    private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
        public void check(UserDetails user) {
            if(user instanceof IntegrationUser){
                user = (IntegrationUser)user;
                if (!user.isAccountNonLocked()) {
                    if (log.isDebugEnabled()) {
                        log.debug("User account is locked");
                    }
                    throw new LockedException(messages.getMessage(
                            "AbstractUserDetailsAuthenticationProvider.locked",
                            "用户已被锁定"));
                }
                if(((IntegrationUser) user).isDeleted()){
                    if (log.isDebugEnabled()) {
                        log.debug("User account is deleted");
                    }
                    throw new DeletedException(messages.getMessage(
                            "AbstractUserDetailsAuthenticationProvider.deleted",
                            "用户已删除"));
                }

                if (!user.isEnabled()) {
                    if (log.isDebugEnabled()) {
                        log.debug("User account is disabled");
                    }
                    throw new DisabledException(messages.getMessage(
                            "AbstractUserDetailsAuthenticationProvider.disabled",
                            "此账号已被禁用 有问题请联系客服"));
                }

                if (!user.isAccountNonExpired()) {
                    if (log.isDebugEnabled()) {
                        log.debug("User account is expired");
                    }
                    throw new AccountExpiredException(messages.getMessage(
                            "AbstractUserDetailsAuthenticationProvider.expired",
                            "账户已过期"));
                }
            }
        }
    }

    private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
        public void check(UserDetails user) {
            if (!user.isCredentialsNonExpired()) {
                if (log.isDebugEnabled()) {

                    log.debug("User account credentials have expired");
                }

                throw new CredentialsExpiredException(messages.getMessage(
                        "AbstractUserDetailsAuthenticationProvider.credentialsExpired",
                        "User credentials have expired"));
            }
        }
    }

}
