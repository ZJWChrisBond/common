package com.zjw.common.utils.time;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.time
 * @Date: Created in   2019/10/23 15:40
 * @Modified By:
 * @since 1.0
 */
class TimeUtilsTest {
    private static final Logger LOG = LoggerFactory.getLogger(TimeUtilsTest.class);
    private static long THRESHOLD = 24 * 3600000;//86400000毫秒 ==（24小时）
    TimeUtils utils;

    @BeforeEach
    void setUp() {
        LOG.info("==================开始测试时间工具===========");
        utils = new TimeUtils();
    }

    @AfterEach
    void tearDown() {
        LOG.info("==================结束测试时间工具===========");
    }

    @Test
    void isExpireTime() {
        //判断存在是否超过24小时  2019-10-21 15:47:07 -》1571644027  单位s
        boolean expireTime = utils.isExpireTime(1571644027, THRESHOLD);
        assertTrue(expireTime);
    }

    @Test
    void nowString() {
        LOG.info("===============当前时间===" + utils.nowString());
    }

    @Test
    void getSysYear() {
        LOG.info("===============当前系统时间的年===" + utils.getSysYear());
    }

    @Test
    void getCurrentYear() {
        LOG.info("===============当前时间的年===" + utils.getCurrentYear());
    }

    @Test
    void dateToStamp() throws ParseException {
        //2019-10-21 15:47:07 -》1571644027000  单位ms
        String stamp = utils.dateToStamp("2019-10-21 15:47:07");
        assertEquals("1571644027000", stamp);
    }

    @Test
    void stampToDate() {
        //判断存在是否超过24小时  2019-10-21 15:47:07 -》  单位ms
        String date = utils.stampToDate("1571644027000");
        assertEquals("2019-10-21 15:47:07", date);
    }
}