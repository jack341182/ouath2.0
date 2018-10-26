package com.auth.provider.config.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class IntegrationExceptionTranslator<E extends OAuth2Exception> extends DefaultWebResponseExceptionTranslator {
    @Override
    public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
//        log.info("====》  处理异常信息 [exception ]" + e.getClass().getName());

        log.info(e.getClass().getName());
        if (e instanceof InvalidGrantException) {
            if (e.getMessage().equalsIgnoreCase("坏的凭证")) {
                return new ResponseEntity(new InvalidGrantException("用户名或密码错误"), HttpStatus.UNAUTHORIZED);
            }
            if (e.getMessage().equalsIgnoreCase("用户已失效")) {
                return new ResponseEntity(new InvalidGrantException("此账号已被禁用 有问题请联系客服"), HttpStatus.UNAUTHORIZED);
            }
        }
        return super.translate(e);
    }
}
