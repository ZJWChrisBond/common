package com.zjw.common.utils.helper;

import com.zjw.common.lang.Try;
import freemarker.cache.StringTemplateLoader;
import freemarker.ext.beans.BeansWrapper;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateModel;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;
import org.springframework.util.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 字符串模板引擎
 *
 * @author zjw
 */
public class TemplateBuilder {


    /**
     * @param tmpl    模板内容，如："hello,我是${name}"
     * @param context 编译上下文
     */
    public static String build(String tmpl, Object context) {
        return Try.rethrow(() -> {
            String htmlStr = "";
            String templateName = DigestUtils.md5DigestAsHex(tmpl.getBytes(StandardCharsets.UTF_8));
            Configuration configuration = configuration();
            Template template = new Template(templateName, tmpl, configuration);
            htmlStr = FreeMarkerTemplateUtils.processTemplateIntoString(template, context);
            return htmlStr;
        });
    }

    /**
     * 上下文增加static model
     */
    public static String buildWithBeanWrapper(String tmpl, Map<String, Object> context, Class<?>... cls) {
        return Try.rethrow(() -> {
            String htmlStr = "";
            String templateName = DigestUtils.md5DigestAsHex(tmpl.getBytes(StandardCharsets.UTF_8));
            Configuration configuration = configuration();
            BeansWrapper wrapper = new BeansWrapper(Configuration.VERSION_2_3_27);
            if (cls.length > 0) {
                for (Class c : cls) {
                    TemplateModel model = wrapper.getStaticModels().get(c.getName());
                    configuration.setObjectWrapper(wrapper);
                    context.put(c.getSimpleName(), model);
                }
            }
            Template template = new Template(templateName, tmpl, configuration);
            htmlStr = FreeMarkerTemplateUtils.processTemplateIntoString(template, context);
            return htmlStr;
        });
    }


    private static Configuration configuration() {
        Configuration configuration = new Configuration(Configuration.VERSION_2_3_27);
        StringTemplateLoader templateLoader = new StringTemplateLoader();
        configuration.setTemplateLoader(templateLoader);
        configuration.setDefaultEncoding("UTF-8");
        return configuration;
    }
}
