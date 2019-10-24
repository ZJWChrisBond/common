package com.zjw.common.utils.uid;

import java.util.Random;
import java.util.UUID;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 获取唯一的值
 * @Date: Created in   2019/10/24 10:55
 * @Modified By:
 * @since 1.0
 */
public class UUIDUtils {
    public static String getKid(){
        String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 22; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }
    public static String getGUID(){
        return UUID.randomUUID().toString();
    }

}
