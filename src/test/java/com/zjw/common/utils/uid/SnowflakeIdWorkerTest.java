package com.zjw.common.utils.uid;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.uid
 * @Date: Created in   2019/10/23 16:08
 * @Modified By:
 * @since 1.0
 */
class SnowflakeIdWorkerTest {
    private static final Logger LOG = LoggerFactory.getLogger(SnowflakeIdWorkerTest.class);
    @BeforeEach
    void setUp() {
        LOG.info("==================开始测试唯一雪花ID工具===========");
    }

    @AfterEach
    void tearDown() {
        LOG.info("==================结束测试唯一雪花ID工具===========");
    }
    @Test
    void generateId() {
        System.out.println(SnowflakeIdWorker.generateId());
    }
}