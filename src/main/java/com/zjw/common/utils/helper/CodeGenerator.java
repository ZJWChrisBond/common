package com.zjw.common.utils.helper;

import com.zjw.common.enums.CodeType;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.util.CollectionUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 编码生成器
 *
 * @author zjw
 */
public class CodeGenerator {

    protected static final String NUMBER = "123456789";
    protected static final String ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ";
    protected static final String SPECIAL_ALPHABET = "$@—_?&*%#!";

    private static final Map<String, Object> CODE_TYPE_MAPPINGS = new HashMap<>();

    static {
        CODE_TYPE_MAPPINGS.put(CodeType.CHAR.getValue(), ALPHABET);
        CODE_TYPE_MAPPINGS.put(CodeType.NUMBER.getValue(), NUMBER);
        CODE_TYPE_MAPPINGS.put(CodeType.SPECIAL_CODE.getValue(), SPECIAL_ALPHABET);
    }

    /**
     * 按要求的字符类型，随机生成指定长度的编码
     */
    public static String random(int length, CodeType... types) {
        StringBuilder letters = new StringBuilder();
        if (types == null) {
            letters.append(NUMBER);
        } else {
            for (CodeType type : types) {
                letters.append(CODE_TYPE_MAPPINGS.get(type.getValue()));
            }
        }
        return RandomStringUtils.random(length, letters.toString());
    }

    public static String random(int length, List<CodeType> types) {
        return random(length, CollectionUtils.isEmpty(types) ? null : types.toArray(new CodeType[0]));
    }
}
