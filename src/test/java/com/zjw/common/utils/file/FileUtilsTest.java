package com.zjw.common.utils.file;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.file
 * @Date: Created in   2019/10/24 10:05
 * @Modified By:
 * @since 1.0
 */
class FileUtilsTest {
    private static final Logger LOG = LoggerFactory.getLogger(FileUtilsTest.class);
    @BeforeEach
    void setUp() {
        LOG.info("==================开始测试文件操作工具===========");
    }

    @AfterEach
    void tearDown() {
        LOG.info("==================结束测试文件操作工具===========");
    }
    @Test
    void test() throws IOException {
        LOG.info("=============读取文件");
        String path="files/test.txt";
        assertEquals(2,FileUtils.countString(path,"测试"));
    }
}