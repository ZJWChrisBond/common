package com.zjw.common.utils.validate;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import org.hibernate.validator.constraints.Length;

@Valid
public class ValidateModel {

    @NotNull
    private String name;

    @Length(min = 1, max = 5, message = "不能超过150")
    @NotNull
    protected String title;

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
