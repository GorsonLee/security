package com.gorson.securitydemo.web.controller;

import com.fasterxml.jackson.annotation.JsonView;
import com.gorson.securitydemo.dto.User;
import com.gorson.securitydemo.dto.UserQueryCondition;
import com.gorson.securitydemo.exception.UserNotExistException;
import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    /**
     * 测试RestFul返回JsonString的测试，并使用条件类进行查询数据，测试JsonView
     * JsonView的步骤：
     * 1.在实体类中添加JsonView的接口；
     * 2.在实体类中的get方法上指定添加使用的JsonView
     * 3.在Api上指定使用的JsonView
     *
     * @param condition 查询条件类
     * @return
     */
    @JsonView(User.UserDetailView.class)
    @GetMapping("/getUserList")
    public List<User> getUser(UserQueryCondition condition) {
        System.out.println(ReflectionToStringBuilder.toString(condition, ToStringStyle.MULTI_LINE_STYLE));
        List<User> userList = new ArrayList<>();
        userList.add(new User());
        userList.add(new User());
        userList.add(new User());
        return userList;
    }

    /**
     * 使用正则表达式指定传入数据的类型
     *
     * @param id
     * @return
     */
    @JsonView(User.UserSimpleView.class)
    @GetMapping("/getUser/{id:\\d+}")
    public User getUser(@PathVariable String id) {
        return new User();
    }

    /**
     * 使用RequestBody注解封装对象，使用Valid验证信息，配合BingingResult处理错误数据
     *
     * @param user  请求的用户信息
     * @param error Valid校验的错误信息
     * @return
     */
    @PostMapping("/createUser")
    public User createUser(@Valid @RequestBody User user, BindingResult error) {
        //如果存在错误，遍历错误打印出来
        if (error.hasErrors()) {
            error.getAllErrors().stream().forEach(objectError -> {
//                FieldError fieldError = (FieldError) objectError;
//                System.out.println(fieldError.getField() + " " + fieldError.getDefaultMessage());

                System.out.println("校验信息：" + objectError.getDefaultMessage());
            });
        }

        System.out.println(ReflectionToStringBuilder.toString(user));
        user.setId("1");
        return user;
    }

    @GetMapping("/getUserException/{id}")
    public User getUserException(@PathVariable String id) {
        throw new UserNotExistException(id);
    }
}
