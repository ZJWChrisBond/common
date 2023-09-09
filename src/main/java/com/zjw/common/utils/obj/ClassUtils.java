package com.zjw.common.utils.obj;

import java.util.Arrays;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 类工具
 * @Date: Created in   2019/10/24 13:14
 * @Modified By:
 * @since 1.0
 */
public class ClassUtils {

    /**
     * 判断2个类是否实现相同的接口，包括接口的继承关系
     *
     * @param aClass
     * @param bClass
     * @return
     */
    public static boolean hasSameAssignableInterface(Class aClass, Class bClass) {
        Class[] aInterfaces = aClass.getInterfaces();
        //判断类A的接口是否是类B的接口
        boolean isSame = Arrays.stream(aInterfaces).anyMatch(aInterface -> aInterface.isAssignableFrom(bClass));
        if (!isSame) {
            Class[] bInterfaces = bClass.getInterfaces();
            //判断类B的接口是否是类A的接口的父类
            isSame = Arrays.stream(aInterfaces).anyMatch(
                    aInterface -> Arrays.stream(bInterfaces).anyMatch(
                            bInterface -> bInterface.isAssignableFrom(aInterface)
                    )
            );
        }
        return isSame;
    }

    /**
     * 判断2个类是否是父子关系
     *
     * @param aClass
     * @param bClass
     * @return
     */
    public static boolean isAssignableEachOther(Class aClass, Class bClass) {
        if (aClass.isInterface() || bClass.isInterface()) {
            return false;
        }
        return aClass.isAssignableFrom(bClass) || bClass.isAssignableFrom(aClass);
    }
}
