package com.zjw.common.utils.net;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: for  IP
 * @Date: Created in   2019/10/24 9:19
 * @Modified By:
 * @since 1.0
 */
public class IPUtils {

    public static long IP2Long(String ip) {
        String[] s = ip.split("\\.");
        long ipl = (Long.parseLong(s[0]) << 24) + (Long.parseLong(s[1]) << 16)
                + (Long.parseLong(s[2]) << 8) + (Long.parseLong(s[3]));
        return ipl;
    }


    public static String long2IP(long ipl) {
        long A = ipl >> 24;
        long B = (ipl & 0x00FFFFFF) >> 16;
        long C = (ipl & 0x0000FFFF) >> 8;
        long D = ipl & 0x000000FF;
        return new StringBuffer().append(A).append(".").append(B).append(".")
                .append(C).append(".").append(D).toString();
    }

}
