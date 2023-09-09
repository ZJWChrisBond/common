package com.zjw.common.utils.net;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.net
 * @Date: Created in   2019/10/24 9:20
 * @Modified By:
 * @since 1.0
 */
class IPUtilsTest {

    @Test
    void iptest() {
        String ip = "110.111.112.113";
        long ipl = 1852797041l;
        assertEquals(ipl, IPUtils.IP2Long(ip));

        assertEquals(ip, IPUtils.long2IP(ipl));
    }
}