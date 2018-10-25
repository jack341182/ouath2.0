package com.auth.common;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.io.Serializable;

/**
 * @Auther: vicykie
 * @Date: 2018/8/24 14:37
 * @Description:
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class SmsCodeLogin implements Serializable {
    private String mobile;
    private String smsCode;
    private String deviceId;
}
