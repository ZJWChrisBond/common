package com.zjw.common.utils.helper;

import java.util.Collection;

/**
 * 版本工具
 *
 * @author zjw
 */
public class VersionUtil {

    /**
     * 版本号比较
     * <p>
     * a > b  -> 1
     * <p>
     * a < b  -> -1
     * <p>
     * a = b  -> 0
     */
    public static int compare(String a, String b) {
        if (a.equals(b)) {
            return 0;
        }
        String[] version1Array = a.split("[._]");
        String[] version2Array = b.split("[._]");
        int index = 0;
        int minLen = Math.min(version1Array.length, version2Array.length);
        long diff = 0;

        while (index < minLen
                && (diff = Long.parseLong(version1Array[index])
                - Long.parseLong(version2Array[index])) == 0) {
            index++;
        }
        if (diff == 0) {
            for (int i = index; i < version1Array.length; i++) {
                if (Long.parseLong(version1Array[i]) > 0) {
                    return 1;
                }
            }
            for (int i = index; i < version2Array.length; i++) {
                if (Long.parseLong(version2Array[i]) > 0) {
                    return -1;
                }
            }
            return 0;
        } else {
            return diff > 0 ? 1 : -1;
        }
    }


    /**
     * 找出最大的版本号
     */
    public static String max(Collection<String> versions) {
        return versions.stream().max(VersionUtil::compare).orElse("");
    }
}
