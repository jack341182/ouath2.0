package com.auth.provider.config.properties;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties(prefix = "spring.wechat")
@Configuration
@Data
public class WechatProperties {
    private String getOpenIdUrl = "https://api.weixin.qq.com/sns/jscode2session?appid={appid}&secret={secret}&js_code={js_code}&grant_type={grant_type}";
    @NestedConfigurationProperty
    private WechatCommonProperties trucker;
}

