package com.gorson.securitydemo.web.config;

import com.gorson.securitydemo.web.interceptor.TimeInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.annotation.Resource;

//@Configuration
public class WebInterceptorConfig extends WebMvcConfigurerAdapter {
    @Resource
    private TimeInterceptor timeInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(timeInterceptor);
    }
}
