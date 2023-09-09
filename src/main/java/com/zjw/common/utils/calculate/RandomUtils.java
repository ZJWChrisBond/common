package com.zjw.common.utils.calculate;

import java.util.Random;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 产生一定范围内的随机数
 * @Date: Created in   2019/10/24 11:07
 * @Modified By:
 * @since 1.0
 */
public class RandomUtils {
    /**
     * 在[min,max]产生随机数
     *
     * @param min
     * @param max
     * @return
     */
    public static int getRandomInt(int min, int max) {
        Random rand = new Random();
        int randNumber = rand.nextInt(max - min + 1) + min;
        return randNumber;
    }

    /**
     * 在[min,max]产生随机数  
     *
     * @param min
     * @param max
     * @return
     */
    public static Double getRandomDouble(Double min, Double max) {
        Random rand = new Random();
        Double randNumber = rand.nextDouble() * (max - min) + min;
        return randNumber;
    }
}
