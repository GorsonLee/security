package com.gorson.securitydemo.web.filter;

import javax.servlet.*;
import java.io.IOException;
import java.util.Date;

/**
 * 第三方的过滤器不能声明为Spring的组件时，使用Configuration配置
 * 详细见 {@link com.gorson.securitydemo.web.config.WebFilterConfig}
 */
public class OthersFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("Other filter init");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("Other filter start: " + (new Date()).getTime());
        filterChain.doFilter(servletRequest, servletResponse);
        System.out.println("Other filter finish: " + (new Date()).getTime());
    }

    @Override
    public void destroy() {
        System.out.println("Other filter destroy");
    }

}
