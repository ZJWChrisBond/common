package com.zjw.common.utils.helper;

import net.sourceforge.pinyin4j.PinyinHelper;
import net.sourceforge.pinyin4j.format.HanyuPinyinCaseType;
import net.sourceforge.pinyin4j.format.HanyuPinyinOutputFormat;
import net.sourceforge.pinyin4j.format.HanyuPinyinToneType;
import net.sourceforge.pinyin4j.format.HanyuPinyinVCharType;
import net.sourceforge.pinyin4j.format.exception.BadHanyuPinyinOutputFormatCombination;

/**
 * 拼音工具
 *
 * @author zjw
 */
public class NamePinyinHelper {


    protected static String CHINESE_REGEX = "[\\u4E00-\\u9FA5]+";


    /**
     * 将字符串中的所有中文转化为拼音,其他字符不变
     */
    public static String toPingYin(String name) throws BadHanyuPinyinOutputFormatCombination {
        HanyuPinyinOutputFormat format = new HanyuPinyinOutputFormat();
        format.setCaseType(HanyuPinyinCaseType.LOWERCASE);
        format.setToneType(HanyuPinyinToneType.WITHOUT_TONE);
        format.setVCharType(HanyuPinyinVCharType.WITH_V);

        StringBuilder pinyin = new StringBuilder();

        for (int i = 0, len = name.length(); i < len; i++) {
            char charAt = name.charAt(i);
            if (Character.toString(charAt).matches(CHINESE_REGEX)) {
                pinyin.append(PinyinHelper.toHanyuPinyinStringArray(charAt, format)[0]);
            } else {
                pinyin.append(charAt);
            }
        }
        return pinyin.toString();
    }


    /**
     * 将字符串中的中文拼音首字母，英文字符不变
     */
    protected static String toFirstSpell(String name) throws BadHanyuPinyinOutputFormatCombination {
        HanyuPinyinOutputFormat format = new HanyuPinyinOutputFormat();
        format.setToneType(HanyuPinyinToneType.WITHOUT_TONE);
        format.setVCharType(HanyuPinyinVCharType.WITH_V);

        StringBuilder py = new StringBuilder();

        for (int i = 0, len = name.length(); i < len; i++) {
            char charAt = name.charAt(i);
            if (Character.toString(charAt).matches(CHINESE_REGEX)) {
                String temp = PinyinHelper.toHanyuPinyinStringArray(charAt, format)[0];
                if (null != temp) {
                    py.append(temp.charAt(0));
                }
            } else {
                py.append(charAt);
            }
        }
        return py.toString();
    }

    /**
     * 将字符串中的中文拼音首字母大写
     */
    public static String toUpperFirstSpell(String name) throws BadHanyuPinyinOutputFormatCombination {
        return toFirstSpell(name).toUpperCase();
    }


    /**
     * 将字符串中的中文拼音首字母小写
     */
    public static String toLowerFirstSpell(String name) throws BadHanyuPinyinOutputFormatCombination {
        return toFirstSpell(name).toLowerCase();
    }
}
