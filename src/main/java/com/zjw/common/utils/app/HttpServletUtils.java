package com.zjw.common.utils.app;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.app
 * @Date: Created in   2019/10/24 13:37
 * @Modified By:
 * @since 1.0
 */
public class HttpServletUtils {
    /**
     * 获取HttpServletRequest
     * @return
     */
    public static HttpServletRequest getHttpServletRequest(){
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = servletRequestAttributes.getRequest();
        return request;
    }
    /**
     * 获取HttpServletResponse
     * @return
     */
    public static HttpServletResponse getHttpServletResponse(){
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletResponse response = servletRequestAttributes.getResponse();
        return response ;
    }

}
