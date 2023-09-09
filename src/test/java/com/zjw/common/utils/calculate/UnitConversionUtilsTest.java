package com.zjw.common.utils.calculate;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.calculate
 * @Date: Created in   2019/10/24 11:30
 * @Modified By:
 * @since 1.0
 */
class UnitConversionUtilsTest {

    @Test
    void test() {
        assertEquals(0, DoubleCalcUtils.doubleCompare(12.32, UnitConversionUtils.conversion(new BigDecimal(12323.230),
                UnitConversionUtils.UnitsEnum.LG_M, UnitConversionUtils.UnitsEnum.LG_KM).doubleValue()));
        assertEquals(0, DoubleCalcUtils.doubleCompare(12.323, UnitConversionUtils.conversion(new BigDecimal(12323.230),
                UnitConversionUtils.UnitsEnum.LG_M, UnitConversionUtils.UnitsEnum.LG_KM, 3).doubleValue()));
    }

}