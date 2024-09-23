package com.zjw.common.utils.validate;

import com.zjw.common.utils.helper.Validators;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @version 1.0
 * @Author: zjw
 * @Modified By:
 * @since 1.0
 */
class ValidatorTest {


    private static final Logger LOG = LoggerFactory.getLogger(ValidatorTest.class);

    @BeforeEach
    void setUp() {
        LOG.info("==================开始测试校验字段工具===========");
    }

    @AfterEach
    void tearDown() {
        LOG.info("==================结束测试校验字段工具===========");
    }

    @Test
    void test() {
        ValidateModel model = new ValidateModel();
        model.setName(null);
        model.setTitle("zhgagfeagl");
        Validators.validate(model);

    }

}