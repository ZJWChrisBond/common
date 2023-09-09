package com.zjw.common.enums;


/**
 * 生成验证码类型
 *
 * @author zjw
 */
public enum CodeType implements Valued<String> {
    /**
     * 字母
     */
    CHAR("C"),
    /**
     * 数字
     */
    NUMBER("N"),
    /**
     * 特殊符号
     */
    SPECIAL_CODE("SC");

    private final String value;

    CodeType(String value) {
        this.value = value;
    }

    @Override
    public String getValue() {
        return value;
    }
}
