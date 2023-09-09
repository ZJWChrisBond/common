package com.zjw.common.utils.file;

import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 文件工具
 * @Date: Created in   2019/10/24 9:47
 * @Modified By:
 * @since 1.0
 */
public class FileUtils {

    /**
     * 获取文件,返回内容
     *
     * @param path
     * @return
     * @throws IOException
     */
    public static String getFileContent(String path) throws IOException {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
        String content = reader.lines().collect(Collectors.joining("\n"));
        reader.close();
        return content;
    }

    /**
     * 给定一个txt文件，如何得到某字符串出现的次数
     *
     * @param path
     * @param str
     * @return
     */
    public static int countString(String path, String str) throws IOException {
        String content = getFileContent(path);
        String strs[] = content.split(" |\n");
        return Arrays.stream(strs).filter(item -> !StringUtils.isEmpty(item) && str.equals(item)).collect(Collectors.toList()).size();
    }


}
