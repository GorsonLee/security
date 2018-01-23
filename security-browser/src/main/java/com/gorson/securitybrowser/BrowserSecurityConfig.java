package com.gorson.securitybrowser;

import com.gorson.securitycore.properties.SecurityCoreProperties;
import com.gorson.securitycore.validate.code.ValidateCodeFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

/**
 * 登陆配置
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);

    @Resource
    private SecurityCoreProperties securityCoreProperties;
    @Resource
    private AuthenticationSuccessHandler gorsonAuthenticationSuccessHandler;
    @Resource
    private AuthenticationFailureHandler gorsonAuthenticationFailureHandler;
    @Resource
    private AuthenticationSuccessHandler gorsonAuthenticationSuccessHandlerSelector;
    @Resource
    private AuthenticationFailureHandler gorsonAuthenticationFailureHandlerSelector;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("Browser Security Config");
        ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
        validateCodeFilter.setAuthenticationFailureHandler(gorsonAuthenticationFailureHandlerSelector);
        validateCodeFilter.setSecurityCoreProperties(securityCoreProperties);
        validateCodeFilter.afterPropertiesSet();

        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin() //表单登陆，指定身份认证的方式
                .loginPage("/authentication/require") //是否需要身份验证
                .loginProcessingUrl("/authentication/form") //指定登陆的Action
                .successHandler(gorsonAuthenticationSuccessHandlerSelector) //登陆成功的处理
                .failureHandler(gorsonAuthenticationFailureHandlerSelector) //登陆失败的处理
                .and()
                .authorizeRequests() //授权配置
                .antMatchers("/authentication/require",
                        securityCoreProperties.getBrowser().getLoginPage(), "/code/image").permitAll() //授权登陆界面
                .anyRequest() //任何请求
                .authenticated() //都需要身份认证
                .and()
                .csrf().disable(); //禁用csrf防护
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
