package com.gorson.web.controller.async;

import org.apache.commons.lang.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;

import javax.annotation.Resource;
import java.util.concurrent.Callable;

@RestController
@RequestMapping("/async")
public class AsyncController {
    private Logger logger = LoggerFactory.getLogger(getClass());

    @Resource
    private MockQueue mockQueue;
    @Resource
    private DeferredResultHolder deferredResultHolder;

    @GetMapping("/order/runnable")
    public Callable<String> orderRunnable() {
        logger.info("主线程开始");

        Callable<String> result = () -> {
            logger.info("子线程开始");
            Thread.sleep(1000);
            logger.info("子线程结束");
            return "success";
        };

        logger.info("主线程结束");
        return result;
    }

    @GetMapping("/order/deferredResult")
    public DeferredResult<String> orderDeferredResult() throws InterruptedException {
        logger.info("Order 主线程开始");

        String order = RandomStringUtils.randomAlphanumeric(8);
        mockQueue.setPlaceOrder(order);
        DeferredResult<String> result = new DeferredResult<>();
        deferredResultHolder.getDeferredResultMap().put(order, result);

        logger.info("Order 主线程结束");
        return result;
    }
}
