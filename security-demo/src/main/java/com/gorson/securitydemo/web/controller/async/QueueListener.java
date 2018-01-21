package com.gorson.securitydemo.web.controller.async;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class QueueListener implements ApplicationListener<ContextRefreshedEvent> {
    private Logger logger = LoggerFactory.getLogger(QueueListener.class);

    @Resource
    private MockQueue mockQueue;
    @Resource
    private DeferredResultHolder deferredResultHolder;

    @Override
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {
        //监听器的线程
        new Thread(() -> {
            while (true) {
                //处理数据
                if (StringUtils.isNotBlank(mockQueue.getCompleteOrder())) {
                    String orderNumber = mockQueue.getCompleteOrder();
                    logger.info("返回订单处理结果：" + orderNumber);
                    deferredResultHolder.getDeferredResultMap().get(orderNumber).setResult("订单处理完毕");
                    mockQueue.setCompleteOrder(null); //模拟消息队列将字段设置为空避免一直循环
                } else {
                    //没有数据挂起100ms，然后继续循环
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();
    }
}
