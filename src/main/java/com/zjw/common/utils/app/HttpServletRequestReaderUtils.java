package com.zjw.common.utils.app;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 从 HttpServletRequest 中读取HTTP请求的body内容
 * @Date: Created in   2019/10/24 13:46
 * @Modified By:
 * @since 1.0
 */
public class HttpServletRequestReaderUtils {

    // 字符串读取
    public static String readAsString(HttpServletRequest request) {

        BufferedReader br = null;
        StringBuilder sb = new StringBuilder("");
        try {
            br = request.getReader();
            String str;
            while ((str = br.readLine()) != null) {
                sb.append(str);
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (null != br) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return sb.toString();
    }


    // 二进制读取
    public static byte[] readAsBytes(HttpServletRequest request) {

        int len = request.getContentLength();
        byte[] buffer = new byte[len];
        ServletInputStream in = null;

        try {
            in = request.getInputStream();
            in.read(buffer, 0, len);
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return buffer;
    }

}
