package com.auth.common;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
/**
 * 返回体内容
 */
@Builder
public class Body<T> implements Serializable {
    /**
     * 返回的数据
     */
    private T data;
    /**
     * 自定义返回的消息
     */
    private String message;

    private int status;

    public Body(T data, String message, int status) {
        this.data = data;
        this.message = message;
        this.status = status;
    }

    public Body() {
    }
}
