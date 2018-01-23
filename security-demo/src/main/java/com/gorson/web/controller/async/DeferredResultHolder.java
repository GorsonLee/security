package com.gorson.web.controller.async;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.async.DeferredResult;

import java.util.HashMap;
import java.util.Map;

@Component
public class DeferredResultHolder {
    private Logger logger = LoggerFactory.getLogger(DeferredResultHolder.class);

    private Map<String, DeferredResult<String>> deferredResultMap = new HashMap<>();

    public Map<String, DeferredResult<String>> getDeferredResultMap() {
        logger.info("队列池的任务个数：" + deferredResultMap.size());
        return deferredResultMap;
    }

    public void setDeferredResultMap(Map<String, DeferredResult<String>> deferredResultMap) {
        this.deferredResultMap = deferredResultMap;
    }
}
