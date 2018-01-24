package com.gorson.securitycore.validate.code;

import com.gorson.securitycore.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
public class ValidateCodeController {
    private Logger logger = LoggerFactory.getLogger(ValidateCodeController.class);

    @Resource
    private ValidateCodeProcessorHolder validateCodeProcessorHolder;

    @GetMapping(Constants.VALIDATE_CODE_URL_PREFIX + "/{type}")
    public void createCode(HttpServletRequest request,
                           HttpServletResponse response,
                           @PathVariable String type) throws Exception {
        logger.info("开始请求验证码：" + type);
        validateCodeProcessorHolder.getValidateCodeGenerator(type).create(new ServletWebRequest(request, response));
    }

}
