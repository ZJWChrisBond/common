package com.zjw.common.utils.obj;

import java.io.*;
import java.util.List;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: 对象复制工具
 * @Date: Created in   2019/10/24 9:43
 * @Modified By:
 * @since 1.0
 */
public class CopyUtils {

    /**
     * List<T> destList=deepCopy(srcList);  //调用该方法
     *
     * @param src
     * @param <T>
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static <T> List<T> deepCopy(List<T> src) throws IOException, ClassNotFoundException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(byteOut);
        out.writeObject(src);

        ByteArrayInputStream byteIn = new ByteArrayInputStream(byteOut.toByteArray());
        ObjectInputStream in = new ObjectInputStream(byteIn);
        @SuppressWarnings("unchecked")
        List<T> dest = (List<T>) in.readObject();
        return dest;
    }
}
