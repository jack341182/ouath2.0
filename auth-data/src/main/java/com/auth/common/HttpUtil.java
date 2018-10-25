package com.auth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kybb.common.cloud.integration.SmsCodeLogin;
import com.kybb.common.http.Body;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.codec.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * @Auther: vicykie
 * @Date: 2018/8/23 00:52
 * @Description:
 */
public class HttpUtil {

    /**
     * base64解码请求头 Basic aW1vb2M6aW1vb2NzZWNyZXQ=
     * Decodes the header into a username and password.
     *
     * @throws BadCredentialsException if the Basic header is not present or is not valid
     *                                 Base64
     */
    public static String[] extractAndDecodeHeader(String header, HttpServletRequest request) {
        try {
            //Basic aW1vb2M6aW1vb2NzZWNyZXQ= 截取Basic后的
            byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
            //解码后格式   用户名:密码
            byte[] decoded = Base64.decode(base64Token);
            String token = new String(decoded, StandardCharsets.UTF_8);
            int delim = token.indexOf(":");
            if (delim == -1) {
                throw new BadCredentialsException("Invalid basic authentication token");
            }
            return new String[]{token.substring(0, delim), token.substring(delim + 1)};
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException(
                    "Failed to decode basic authentication token");
        }

    }


    public static SmsCodeLogin getLoginMsg(HttpServletRequest request) {
        SmsCodeLogin login = new SmsCodeLogin();
        login.setDeviceId(request.getHeader("deviceId"));
        login.setMobile(request.getParameter("mobile"));
        login.setSmsCode(request.getParameter("smsCode"));
        return login;
    }


    public static void writeResponse(ObjectMapper objectMapper, String message, HttpServletResponse response) {
       writeResponse(objectMapper,message,response,HttpStatus.BAD_REQUEST);
    }

    public static void writeResponse(ObjectMapper objectMapper, String message, HttpServletResponse response,HttpStatus status) {
        try {
            PrintWriter writer = response.getWriter();
            response.setStatus(status.value());
            writer.write(objectMapper.writeValueAsString(Body.builder().status(status.value()).message(message).build()));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
