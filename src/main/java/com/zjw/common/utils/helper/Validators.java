package com.zjw.common.utils.helper;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.ValidationException;
import javax.validation.Validator;
import javax.validation.groups.Default;

import org.springframework.util.CollectionUtils;

/**
 * 校验工具
 */
public class Validators {

    private static Validator validator = Validation.buildDefaultValidatorFactory().getValidator();


    /**
     * 实体加@javax.validation.Valid
     *         RestApiRequest restApiRequest = Converts.convert(params, RestApiRequest.class);
     *         Map<String, StringBuilder> errorMap = ValidatorUtils.validate(restApiRequest);
     *         if (!errorMap.isEmpty()) {
     *             throw new ValidationException(errorMap.toString());
     *         }
     */
    public static <T> Map<String, StringBuilder> validate(T object, Class<?>... groups) {
        Map<String, StringBuilder> errorMap = new HashMap<>(16);
        if (groups == null) {
            groups = new Class[]{Default.class};
        }
        Set<ConstraintViolation<T>> set = validator.validate(object, groups);
        if (CollectionUtils.isEmpty(set)) {
            return new HashMap<>();
        }
        String property;
        for (ConstraintViolation<T> c : set) {
            property = c.getPropertyPath().toString();
            if (errorMap.get(property) != null) {
                errorMap.get(property).append(",").append(c.getMessage());
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(c.getMessage());
                errorMap.put(property, sb);
            }
        }
        return errorMap;
    }

    /**
     * 错误立刻抛出
     */
    public static <T> void validate(T object) {
        Set<ConstraintViolation<T>> set = validator.validate(object);
        if (CollectionUtils.isEmpty(set)) {
            return;
        }
        StringBuilder error = new StringBuilder();
        set.forEach(item -> {
            error.append(item.getMessage());
        });
        throw new ValidationException(error.toString());
    }

}
