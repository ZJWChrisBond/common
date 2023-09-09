package com.zjw.common.utils.qrcode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.qrcode
 * @Date: Created in   2019/10/24 16:33
 * @Modified By:
 * @since 1.0
 */
class QRCodeUtilsTest {
    @Test
    void test() throws Exception {
        // 存放在二维码中的内容
        String text = "我是zjw";
        // 嵌入二维码的图片路径
        String imgPath = "C:/qrcode/zjw.png";
        // 生成的二维码的路径及名称
        String destPath = "C:/qrcode/qrzjw.jpg";
        //生成二维码
        QRCodeUtils.encode(text, imgPath, destPath, true);
        // 解析二维码
        String str = QRCodeUtils.decode(destPath);
        // 打印出解析出的内容
        System.out.println(str);
    }


}