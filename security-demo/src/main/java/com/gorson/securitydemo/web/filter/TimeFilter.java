package com.gorson.securitydemo.web.filter;

import org.springframework.stereotype.Component;

import javax.servlet.*;
import java.io.IOException;
import java.util.Date;

/**
 * 声明为Spring的组建，则对所有的请求都有效
 */
//@Component
public class TimeFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("Time filter init");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("Time filter start: " + (new Date()).getTime());
        filterChain.doFilter(servletRequest, servletResponse);
        System.out.println("Time filter finish: " + (new Date()).getTime());
    }

    @Override
    public void destroy() {
        System.out.println("Time filter destroy");
    }
}
