package com.gorson.securitycore.validate.code;

import com.gorson.securitycore.properties.SecurityCoreProperties;
import com.gorson.securitycore.validate.code.image.ImageValidateCodeGenerator;
import com.gorson.securitycore.validate.code.model.ValidateCodeGenerator;
import com.gorson.securitycore.validate.code.sms.DefaultSmsCodeSender;
import com.gorson.securitycore.validate.code.sms.SmsCodeSender;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.Resource;

@Configuration
public class ValidateCodeBeanConfig {

	@Resource
	private SecurityCoreProperties securityCoreProperties;

	@Bean
	@ConditionalOnMissingBean(name = "imageValidateCodeGenerator")
	public ValidateCodeGenerator imageValidateCodeGenerator() {
		ImageValidateCodeGenerator imageValidateCodeGenerator = new ImageValidateCodeGenerator();
		imageValidateCodeGenerator.setSecurityCoreProperties(securityCoreProperties);
		return imageValidateCodeGenerator;
	}

	/**
	 * 使用者可以重写提供应用层的短信发送器
	 * @return 短信发送器
	 */
	@Bean
	@ConditionalOnMissingBean(SmsCodeSender.class)
	public SmsCodeSender smsCodeSender() {
		return new DefaultSmsCodeSender();
	}
}
