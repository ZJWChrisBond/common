package com.zjw.common.utils.calculate;

import org.springframework.util.StringUtils;

import java.math.BigDecimal;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 单位转换工具，需要时添加单位即可，以国际单位为标准，如米《=》千米 ：1《=》0.001
 * @Date: Created in   2019/10/24 11:26
 * @Modified By:
 * @since 1.0
 */
public class UnitConversionUtils {

    /**
     * 默认保留两位小数,四舍五入
     * UnitConversionUtils.conversion(new BigDecimal(12323.230),UnitConversionUtils.UnitsEnum.LG_M,
     UnitConversionUtils.UnitsEnum.LG_KM);
     * @param value    原始数值
     * @param original 原始单位
     * @param need     转换的单位
     * @return
     */
    public static BigDecimal conversion(BigDecimal value, UnitsEnum original, UnitsEnum need) {
        return conversion(value, original, need, 2);
    }
    /**
     *
     * @param value    原始数值
     * @param original 原始单位
     * @param need     转换的单位
     * @return
     */
    private static BigDecimal conversion(BigDecimal value, String original, String need) {
        return conversion(value, getUnitEnum(original), getUnitEnum(need));
    }
    /**
     * 四舍五入
     * @param value    原始数值
     * @param original 原始单位
     * @param need     转换的单位
     * @param scale    小数点位数
     * @return
     */
    public static BigDecimal conversion(BigDecimal value, UnitsEnum original, UnitsEnum need, int scale) {
        if (original == UnitsEnum.UN_KNOWN || need == UnitsEnum.UN_KNOWN) {
            throw new IllegalArgumentException("存在不支持的单位参数");
        }
        if (original.category != need.category) {
            throw new IllegalArgumentException("转换单位不统一!" + original.category.name + "不能转换为" + need.category.name);
        }
        return value.multiply(need.rate).divide(original.rate, scale, BigDecimal.ROUND_HALF_UP);
    }




    private static UnitsEnum getUnitEnum(String unit) {
        if (!StringUtils.isEmpty(unit)) {
            for (UnitsEnum unitEnum : UnitsEnum.values()) {
                for (String possibleName : unitEnum.possibleNames) {
                    if (possibleName.equals(unit.toLowerCase())) {
                        return unitEnum;
                    }
                }
            }
        }
        return UnitsEnum.UN_KNOWN;
    }


    public enum UnitsEnum {
        /*长度单位*/
        LG_M(CategoryEnum.LENGTH, "m", new String[]{"m", "米"}, new BigDecimal(1), "米"),
        LG_KM(CategoryEnum.LENGTH, "km", new String[]{"km", "千米"}, new BigDecimal(0.001), "千米"),
        LG_DM(CategoryEnum.LENGTH, "dm", new String[]{"dm", "分米"}, new BigDecimal(10), "分米"),
        LG_CM(CategoryEnum.LENGTH, "cm", new String[]{"cm", "厘米"}, new BigDecimal(100), "厘米"),
        LG_MM(CategoryEnum.LENGTH, "mm", new String[]{"mm", "毫米"}, new BigDecimal(1000), "毫米"),
        LG_UM(CategoryEnum.LENGTH, "um", new String[]{"um", "微米"}, new BigDecimal(1000000), "微米"),
        LG_NM(CategoryEnum.LENGTH, "nm", new String[]{"nm", "纳米"}, new BigDecimal(1000000000), "纳米"),
        LG_INCH(CategoryEnum.LENGTH, "inch", new String[]{"in", "inch", "英寸"}, new BigDecimal(39.3700787), "英寸"),
        LG_MI(CategoryEnum.LENGTH, "mi", new String[]{"mi", "英里"}, new BigDecimal(0.0006214), "英里"),
        LG_FT(CategoryEnum.LENGTH, "ft", new String[]{"ft", "英尺"}, new BigDecimal(3.2808399), "英尺"),
        LG_CHI(CategoryEnum.LENGTH, "尺", new String[]{"尺"}, new BigDecimal(3), "尺"),
        LG_ZHANG(CategoryEnum.LENGTH, "丈", new String[]{"丈"}, new BigDecimal(0.3), "丈"),
        LG_CUN(CategoryEnum.LENGTH, "寸", new String[]{"寸"}, new BigDecimal(30), "寸"),


        /*重量单位*/
        EG_KG(CategoryEnum.WEIGHT, "kg", new String[]{"kg", "千克"}, new BigDecimal(1), "千克"),
        EG_T(CategoryEnum.WEIGHT, "t", new String[]{"t", "吨"}, new BigDecimal(0.001), "吨"),
        EG_G(CategoryEnum.WEIGHT, "g", new String[]{"g", "克"}, new BigDecimal(1000), "克"),
        EG_MG(CategoryEnum.WEIGHT, "mg", new String[]{"mg", "毫克"}, new BigDecimal(1000000), "毫克"),
        EG_UG(CategoryEnum.WEIGHT, "μg", new String[]{"μg", "ug", "微克"}, new BigDecimal(1000000000), "微克"),
        EG_LB(CategoryEnum.WEIGHT, "lb", new String[]{"lb", "lbs", "磅"}, new BigDecimal(2.2046226), "磅"),
        EG_OZ(CategoryEnum.WEIGHT, "oz", new String[]{"oz", "盎司"}, new BigDecimal(35.2739619), "盎司"),
        EG_CT(CategoryEnum.WEIGHT, "ct", new String[]{"ct", "克拉"}, new BigDecimal(5000), "克拉"),

        /*面积单位*/
        AE_M(CategoryEnum.AREA, "㎡", new String[]{"m2","㎡","平方米"}, new BigDecimal(1), "平方米"),
        AE_KM(CategoryEnum.AREA, "km²", new String[]{"km2","km²","平方千米"}, new BigDecimal(1e-6), "平方千米"),
        AE_DM(CategoryEnum.AREA, "dm²", new String[]{"dm2","dm²","平方分米"}, new BigDecimal(100), "平方分米"),
        AE_CM(CategoryEnum.AREA, "cm²", new String[]{"cm2","cm²","平方厘米"}, new BigDecimal(10000), "平方厘米"),
        AE_MM(CategoryEnum.AREA, "mm²", new String[]{"mm2","mm²","平方毫米"}, new BigDecimal(1000000), "平方毫米"),
        AE_HA(CategoryEnum.AREA, "ha", new String[]{"ha","公顷"}, new BigDecimal(0.0001), "公顷"),
        AE_MU(CategoryEnum.AREA, "亩", new String[]{"亩"}, new BigDecimal(0.0015), "亩"),
        AE_ARE(CategoryEnum.AREA, "are", new String[]{"are","公亩"}, new BigDecimal(0.01), "公亩"),
        AE_ACRE(CategoryEnum.AREA, "acre", new String[]{"acre","英亩"}, new BigDecimal(0.0002471), "英亩"),




        /*未知单位*/
        UN_KNOWN(null, "未知", null, new BigDecimal(0), "未知");

        private CategoryEnum category;
        private String units;
        private String[] possibleNames;
        private BigDecimal rate;
        private String description;

        UnitsEnum(CategoryEnum category, String units, String[] possibleNames, BigDecimal rate, String description) {
            this.category = category;
            this.units = units;
            this.possibleNames = possibleNames;
            this.rate = rate;
            this.description = description;
        }

        public CategoryEnum getCategory() {
            return category;
        }

        public String getUnits() {
            return units;
        }

        public String[] getPossibleNames() {
            return possibleNames;
        }

        public BigDecimal getRate() {
            return rate;
        }

        public String getDescription() {
            return description;
        }


        private enum CategoryEnum {
            /*类别：国际单位*/
            LENGTH("length", UnitsEnum.LG_M, "长度"),
            WEIGHT("weight", UnitsEnum.EG_KG, "重量"),
            AREA("area",UnitsEnum.AE_M, "面积");


            private String name;
            private UnitsEnum base;
            private String description;

            CategoryEnum(String name, UnitsEnum base, String description) {
                this.name = name;
                this.base = base;
                this.description = description;
            }

            public String getName() {
                return name;
            }

            public UnitsEnum getBase() {
                return base;
            }

            public String getDescription() {
                return description;
            }
        }

    }
}
