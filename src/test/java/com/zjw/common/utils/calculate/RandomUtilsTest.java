package com.zjw.common.utils.calculate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.calculate
 * @Date: Created in   2019/10/24 11:09
 * @Modified By:
 * @since 1.0
 */
class RandomUtilsTest {
    @Test
    void test() {
        for (int i = 0; i < 50; i++) {
            int num = RandomUtils.getRandomInt(3, 12);
            assertTrue(num <= 12 && num >= 3);
        }
        for (int i = 0; i < 50; i++) {
            double num = RandomUtils.getRandomDouble(10D, 13D);
            assertTrue(DoubleCalcUtils.doubleCompare(num, 10D) >= 0 && DoubleCalcUtils.doubleCompare(num, 20D) <= 0);
        }
    }

}