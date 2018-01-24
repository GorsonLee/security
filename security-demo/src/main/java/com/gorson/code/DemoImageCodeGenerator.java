package com.gorson.code;

import com.gorson.securitycore.validate.code.model.ValidateCode;
import com.gorson.securitycore.validate.code.model.ValidateCodeGenerator;
import org.springframework.web.context.request.ServletWebRequest;

//@Component("imageValidateCodeGenerator")
public class DemoImageCodeGenerator implements ValidateCodeGenerator {
    @Override
    public ValidateCode generate(ServletWebRequest request) {
        System.out.println("应用级的验证码生成器");
        return null;
    }
}
