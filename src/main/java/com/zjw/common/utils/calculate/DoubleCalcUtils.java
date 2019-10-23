package com.zjw.common.utils.calculate;

import java.math.BigDecimal;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: double型数据计算，确保精度
 * @Date: Created in   2019/10/23 17:56
 * @Modified By:
 * @since 1.0
 */
public class DoubleCalcUtils {

    /**
     * 修改精度
     * change precision
     * @param value
     * @param num
     * @return
     */
    public static double changeDecimal(double value, int num) {
        BigDecimal b = new BigDecimal(value);
        double v = b.setScale(num, 4).doubleValue();
        return v;
    }

    /**
     * 两个double相加方法
     *  a+b
     * @param a
     * @param b
     * @return
     */
    public static Double doubleAdd(Double a, Double b) {
        BigDecimal b1 = new BigDecimal(Double.toString(a));
        BigDecimal b2 = new BigDecimal(Double.toString(b));
        return b1.add(b2).doubleValue();
    }

    /**
     * 两个double相加方法,并保留指定精度
     *  a+b save assigned precision
     * @param a
     * @param b
     * @param num
     * @return
     */
    public static Double doubleAdd(Double a, Double b, int num) {
        return changeDecimal(doubleAdd(a, b), num);
    }

    /**
     * 两个double相减方法
     * a-b
     * @param a
     * @param b
     * @return
     */
    public static Double doubleSub(Double a, Double b) {
        BigDecimal b1 = new BigDecimal(Double.toString(a));
        BigDecimal b2 = new BigDecimal(Double.toString(b));
        return b1.subtract(b2).doubleValue();
    }

    /**
     * 两个double相减方法,并保留指定精度
     * a-b save assigned precision
     * @param a
     * @param b
     * @param num
     * @return
     */
    public static Double doubleSub(Double a, Double b, int num) {
        return changeDecimal(doubleSub(a, b), num);
    }

    /**
     * 两个double相乘方法
     * a*b
     * @param a
     * @param b
     * @return
     */
    public static Double doubleMul(Double a, Double b) {
        BigDecimal b1 = new BigDecimal(Double.toString(a));
        BigDecimal b2 = new BigDecimal(Double.toString(b));
        return b1.multiply(b2).doubleValue();
    }

    /**
     * 两个double相乘方法,并保留指定精度
     * a*b save assigned precision
     * @param a
     * @param b
     * @param num
     * @return
     */
    public static Double doubleMul(Double a, Double b, int num) {
        return changeDecimal(doubleMul(a, b), num);
    }

    /**
     * 两个double相除方法,并保留指定精度
     * a/b  save assigned precision
     * @param a
     * @param b
     * @param scale
     * @return
     */
    public static Double doubleDiv(Double a, Double b, int scale) {
        if(b==null||b==0D){
            return 0D;
        }
        BigDecimal b1 = new BigDecimal(Double.toString(a));
        BigDecimal b2 = new BigDecimal(Double.toString(b));
        return Double.valueOf(b1.divide(b2, scale, 4).doubleValue());
    }


    /**
     * 使用两个Double比较大小
     * a>b -->return 1,
     * a=b -->return 0,
     * a<b -->return -1,
     * @param a
     * @param b
     * @return
     */
    public static int doubleCompare(Double a, Double b) {
        if(a==null){
            a=0.0D;
        }
        if(b==null){
            b=0.0D;
        }
        BigDecimal a1 = new BigDecimal(Double.toString(a.doubleValue()));
        BigDecimal b1 = new BigDecimal(Double.toString(b.doubleValue()));
        int num=a1.compareTo(b1);
        return num;
    }
}
