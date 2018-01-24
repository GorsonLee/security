package com.gorson.securitycore.validate.code.sms;

import com.gorson.securitycore.properties.SecurityCoreProperties;
import com.gorson.securitycore.validate.code.model.ValidateCode;
import com.gorson.securitycore.validate.code.model.ValidateCodeGenerator;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;

@Component("smsValidateCodeGenerator")
public class SmsValidateCodeGenerator implements ValidateCodeGenerator {

	@Autowired
	private SecurityCoreProperties securityCoreProperties;
	
	@Override
	public ValidateCode generate(ServletWebRequest request) {
		String code = RandomStringUtils.randomNumeric(securityCoreProperties.getCode().getSms().getLength());
		return new ValidateCode(code, securityCoreProperties.getCode().getSms().getExpireIn());
	}

	public SecurityCoreProperties getSecurityCoreProperties() {
		return securityCoreProperties;
	}

	public void setSecurityCoreProperties(SecurityCoreProperties securityCoreProperties) {
		this.securityCoreProperties = securityCoreProperties;
	}
}
