package com.gorson.web.aspect;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

//@Aspect
//@Component
public class TimeAspect {
    @Around("execution(* UserController.*(..))")
    public Object handlerUserControllerAspect(ProceedingJoinPoint joinPoint) throws Throwable {
        System.out.println("Time aspect start!");

        Object[] args = joinPoint.getArgs();
        for (Object arg : args) {
            System.out.println("arg is: " + arg);
        }

        //获取被拦截的方法
        Object object = joinPoint.proceed();

        System.out.println("Time aspect end!");
        return object;
    }
}
