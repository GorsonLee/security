package com.gorson.securitycore.validate.code.model;

import org.springframework.web.context.request.ServletWebRequest;

public interface ValidateCodeGenerator {

	ValidateCode generate(ServletWebRequest request);
	
}
