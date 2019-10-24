package com.zjw.common.utils.endecrypt;

import java.security.MessageDigest;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 加密工具类 方法命名方法：encrypt+By+加密方式
 * @Date: Created in   2019/10/24 13:35
 * @Modified By:
 * @since 1.0
 */
public class EncryptUtils {
    /**
     * MD5加密
     * @param plainText
     * @return
     */
    public static String encryptByMd5(String plainText) {
        StringBuffer buf = new StringBuffer("");
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(plainText.getBytes());
            byte b[] = md.digest();
            int i = 0;
            for (int offset = 0; offset < b.length; offset++) {
                i = b[offset];
                if (i < 0)
                    i += 256;
                if (i < 16)
                    buf.append("0");
                buf.append(Integer.toHexString(i));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return buf.toString();
    }
}
