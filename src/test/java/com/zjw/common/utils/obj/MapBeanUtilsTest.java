package com.zjw.common.utils.obj;

import org.junit.jupiter.api.Test;

/**
 * @version 1.0
 * @Author: zjw
 * @Description: com.zjw.common.utils.obj
 * @Date: Created in   2019/10/24 13:28
 * @Modified By:
 * @since 1.0
 */
class MapBeanUtilsTest {

    class User{
        public Integer getId() {
            return id;
        }

        public void setId(Integer id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        private Integer id;
        private String  name;
    }

    @Test
    void test(){
        User  user=new User();
        user.setId(3);
        user.setName("ddd");
        MapBeanUtils.beanToMap(user);
    }

}