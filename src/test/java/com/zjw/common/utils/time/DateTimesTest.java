package com.zjw.common.utils.time;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.time.LocalDateTime;


/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.time
 * @Date: Created in   2019/10/23 15:40
 * @Modified By:
 * @since 1.0
 */
class DateTimesTest {
    private static final Logger LOG = LoggerFactory.getLogger(DateTimesTest.class);
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
    void stringToTime() {
        String time = "2019-10-23 15:40:00";
        LocalDateTime localDateTime = DateTimes.parseLocalDateTime(time);
        Timestamp timestamp = DateTimes.parseTimestamp(time);
        DateTimes.parseLocalDate(time);
        time = "2019-10-23 15:40:00.123";
        time = "2019-10-23T15:40:00.123";
        time = "2019-10-23T15:40:00.123Z";
        time = "2019-10-23T15:40:00.123+08:00";

        time = "2019-10-23T15:40:00";
        time = "2019-10-23T15:40:00Z";
        time = "2019-10-23T15:40:00+08:00";


    }

}