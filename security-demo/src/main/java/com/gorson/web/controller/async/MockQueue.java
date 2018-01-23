package com.gorson.web.controller.async;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 模拟订单的队列
 */
@Component
public class MockQueue {
    private Logger logger = LoggerFactory.getLogger(MockQueue.class);

    private String placeOrder; //有订单
    private String completeOrder; //订单完成

    public String getPlaceOrder() {
        return placeOrder;
    }

    /**
     * 模拟下单的耗时处理
     *
     * @param placeOrder
     * @throws InterruptedException
     */
    public void setPlaceOrder(final String placeOrder) throws InterruptedException {
        new Thread(() -> {
            logger.info("Order队列接到下单请求");

            //处理业务逻辑
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            completeOrder = placeOrder;
            logger.info("Order队列下单请求处理完毕");
        }).start();
       }

    public String getCompleteOrder() {
        return completeOrder;
    }

    public void setCompleteOrder(String completeOrder) {
        this.completeOrder = completeOrder;
    }
}
