package com.gorson.web.interceptor;

import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

//@Component
public class TimeInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o) throws Exception {
        //请求之前调用
        System.out.println("TimeInterceptor preHandle");

        //获取类名和方法名
        System.out.println(((HandlerMethod)o).getBean().getClass().getName());
        System.out.println(((HandlerMethod)o).getMethod().getName());

        //设置属性
        httpServletRequest.setAttribute("startTime", new Date().getTime());
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, ModelAndView modelAndView) throws Exception {
        //当Controller抛出异常，则不调用
        System.out.println("TimeInterceptor postHandle");

        Long timestamp = (Long) httpServletRequest.getAttribute("startTime");
        System.out.println("TimeInterceptor execute time: " + (new Date().getTime() - timestamp));
    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) throws Exception {
        //任何情况都会在请求结束后调用
        System.out.println("TimeInterceptor afterCompletion");

        Long timestamp = (Long) httpServletRequest.getAttribute("startTime");
        System.out.println("TimeInterceptor execute time: " + (new Date().getTime() - timestamp));
        System.out.println("TimeInterceptor exception: " + e);
    }
}
