package com.gorson.securitybrowser;

import com.gorson.securitycore.Constants;
import com.gorson.securitycore.authentication.AbstractChannelSecurityConfig;
import com.gorson.securitycore.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.gorson.securitycore.properties.SecurityCoreProperties;
import com.gorson.securitycore.validate.code.ValidateCodeFilter;
import com.gorson.securitycore.validate.code.ValidateCodeSecurityConfig;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.annotation.Resource;

/**
 * 登陆配置
 */
@Configuration
public class BrowserSecurityConfig extends AbstractChannelSecurityConfig {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);

    @Resource
    private SecurityCoreProperties securityCoreProperties; //属性配置
    @Resource
    private ValidateCodeSecurityConfig validateCodeSecurityConfig; //验证码校验器
    @Resource
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig; //短信认证配置
    @Resource
    private DataSource dataSource; //记住我的数据库
    @Resource
    private UserDetailsService userDetailsService; //记住我使用的用户信息服务

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
//        tokenRepository.setCreateTableOnStartup(true); //启动的时候自动创建表
        return tokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("Browser Security Config");
        applyPasswordAuthenticationConfig(http); //构建基本的验证页面和信息

        http.apply(validateCodeSecurityConfig) //校验验证码
                .and()
            .apply(smsCodeAuthenticationSecurityConfig) //短信认证身份
                .and()
            .rememberMe() //记住我
                .tokenRepository(persistentTokenRepository()) //配置记住我的数据库
                .tokenValiditySeconds(securityCoreProperties.getBrowser().getRememberMeSeconds()) //配置Token超时时间
                .userDetailsService(userDetailsService) //配置Token的密码验证
                .and()
            .authorizeRequests() //授权配置
                .antMatchers(Constants.LOGIN_URL_REQUIRE,
                        securityCoreProperties.getBrowser().getLoginPage(),
                        Constants.VALIDATE_CODE_URL_PREFIX + "/*")
                    .permitAll() //授权登陆界面
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
