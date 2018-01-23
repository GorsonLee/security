package com.gorson.securitycore.validate.code;

import com.gorson.securitycore.properties.SecurityCoreProperties;
import com.gorson.securitycore.validate.code.image.ImageCodeGenerator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.Resource;

@Configuration
public class ValidateCodeBeanConfig {
	
	@Resource
	private SecurityCoreProperties securityCoreProperties;
	
	@Bean
	@ConditionalOnMissingBean(name = "imageCodeGenerator")
	public ValidateCodeGenerator imageCodeGenerator() {
		ImageCodeGenerator imageCodeGenerator = new ImageCodeGenerator();
		imageCodeGenerator.setSecurityCoreProperties(securityCoreProperties);
		return imageCodeGenerator;
	}
}
