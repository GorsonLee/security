package com.gorson.securitycore.authentication;

import com.gorson.securitycore.Constants;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.annotation.Resource;

public class AbstractChannelSecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    private AuthenticationSuccessHandler authenticationSuccessHandler; //验证成功的处理
    @Resource
    private AuthenticationFailureHandler authenticationFailureHandler; //验证失败的处理

	/**
	 * 配置认证请求链接，认证事件，认证成功和失败处理器
	 *
	 * @param http
	 * @throws Exception
	 */
	protected void applyPasswordAuthenticationConfig(HttpSecurity http) throws Exception {
		http.formLogin() //表单登陆，指定身份认证的方式
			.loginPage(Constants.LOGIN_URL_REQUIRE) //是否需要身份验证
			.loginProcessingUrl(Constants.LOGIN_URL_FORM) //指定登陆的Action
			.successHandler(authenticationSuccessHandler) //登陆成功的处理器
			.failureHandler(authenticationFailureHandler); //登陆失败的处理器
	}
}
