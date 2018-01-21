package com.gorson.securitybrowser;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() //表单登陆，指定身份认证的方式
                .and()
                .authorizeRequests() //授权配置
                .anyRequest() //任何请求
                .authenticated(); //都需要身份认证
    }
}
