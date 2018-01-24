package com.gorson.securitycore.validate.code;

import com.gorson.securitycore.exception.ValidateCodeException;
import com.gorson.securitycore.validate.code.model.ValidateCodeType;
import com.gorson.securitycore.validate.code.processor.ValidateCodeProcessor;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Map;

@Component
public class ValidateCodeProcessorHolder {

    @Resource
    private Map<String, ValidateCodeProcessor> validateCodeProcessorMap;

    public ValidateCodeProcessor getValidateCodeGenerator(ValidateCodeType type) {
        return getValidateCodeGenerator(type.toString().toLowerCase());
    }

    public ValidateCodeProcessor getValidateCodeGenerator(String type) {
        String name = type.toLowerCase() + ValidateCodeProcessor.class.getSimpleName();
        ValidateCodeProcessor processor = validateCodeProcessorMap.get(name);

        if (processor == null) {
            throw new ValidateCodeException("验证码处理器" + name + "不存在");
        }

        return processor;
    }
}
