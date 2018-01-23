package com.gorson.dto;

import com.fasterxml.jackson.annotation.JsonView;
import com.gorson.validator.MyConstraint;
import org.hibernate.validator.constraints.NotBlank;

import java.util.Date;

public class User {

    //不同场景的JsonView视图
    public interface UserSimpleView {}
    public interface UserDetailView extends UserSimpleView {}

    private String id;
    @MyConstraint(message = "自定义测试注解校验器")
    private String username;
    @NotBlank(message = "密码不能为空") //注解用于验证，message为提示信息
    private String password;
    private Date birthday;

    @JsonView(UserSimpleView.class)
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonView(UserDetailView.class)
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @JsonView(UserSimpleView.class)
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @JsonView(UserSimpleView.class)
    public Date getBirthday() {
        return birthday;
    }

    public void setBirthday(Date birthday) {
        this.birthday = birthday;
    }
}
