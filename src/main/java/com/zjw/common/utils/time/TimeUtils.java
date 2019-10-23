package com.zjw.common.utils.time;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 有关时间的工具类
 * @Date: Created in   2019/10/23 14:52
 * @Modified By:
 * @since 1.0
 */
public class TimeUtils {
    private static final Logger LOG = LoggerFactory.getLogger(TimeUtils.class);

    /**判断存在时间是否超过threshold,单位毫秒**/
    public static boolean isExpireTime(long time,long threshold){
        return System.currentTimeMillis() - time > threshold;
    }
    /**
     * 当前时间
     * @return
     */
    public static String nowString () {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//设置日期格式
        return  df.format(new Date());  // new Date()为获取当前系统时间
    }
    /**
     * 获取系统的年
     * @return
     */
    public static String getSysYear() {
        Calendar date = Calendar.getInstance();
        String year = String.valueOf(date.get(Calendar.YEAR));
        return year;
    }

    /**
     * 获取当前的年
     * @return
     */
    public static String getCurrentYear(){
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy");
        Date date = new Date();
        return sdf.format(date);
    }

    /**
     * 将时间转换为时间戳
     */
    public static String dateToStamp(String s) throws ParseException {
        String res;
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = simpleDateFormat.parse(s);
        long ts = date.getTime();
        res = String.valueOf(ts);
        return res;
    }
    /**
     * 将时间戳转换为时间
     */
    public static String stampToDate(String s){
        String res;
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        long lt = new Long(s);
        Date date = new Date(lt);
        res = simpleDateFormat.format(date);
        return res;
    }

}
