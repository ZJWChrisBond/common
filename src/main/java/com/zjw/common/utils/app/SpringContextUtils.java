package com.zjw.common.utils.app;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 上下文相关工具
 * @Date: Created in   2019/10/24 13:20
 * @Modified By:
 * @since 1.0
 */
@Component
public class SpringContextUtils implements ApplicationContextAware {
    /**
     * Spring应用上下文环境
     */
    private static ApplicationContext applicationContext;

    /**
     * 实现ApplicationContextAware接口的回调方法。设置上下文环境
     *
     * @param applicationContext
     */
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        SpringContextUtils.applicationContext = applicationContext;
    }

    /**
     * @return ApplicationContext
     */
    public static ApplicationContext getApplicationContext() {
        return applicationContext;
    }

    /**
     * 获取对象
     *
     * @param name
     * @return Object
     * @throws BeansException
     */
    public static Object getBean(String name) throws BeansException {
        return applicationContext.getBean(name);
    }

    /**
     * 获取对象通过Class
     *
     * @param cls
     * @return Object
     * @throws BeansException
     */
    public static <C> Object getBean(Class<C> cls) throws BeansException {
        return applicationContext.getBean(cls);
    }


}
