package com.auth.provider.constants;

/**
 * @Auther: vicykie
 * @Date: 2018/8/23 15:00
 * @Description:
 */
public class AuthorizationServerConstants {
    /**
     * 验证码登录
     */
    public static final String SMS_CODE_LOGIN_URL = "/auth/mobile";
    public static final String SMS_CODE_LOGIN_URL_PARAME = "mobile";

    public static final String SMS_CODE_PREFIX = "@_SMS_CODE_@";
    /**
     * 小程序/公众号
     */
    public static final String WECHAT_LOGIN_URL = "/auth/wechat";
    public static final String WECHAT_LOGIN_URL_PARAME = "wxLoginCode";

    public static final String WECHAT_PREFIX = "@_WECHAT_@";


    public static final String URL_SPLIT = " : ";


    public static final String REDIS_SPACE_ROLE = "role.authorities";
}
