package com.gorson.securitycore.validate.code.processor;

import org.springframework.web.context.request.ServletWebRequest;

public interface ValidateCodeProcessor {

	/**
	 * 创建，存储和发送验证码
	 * @param request
	 * @throws Exception
	 */
	void create(ServletWebRequest request) throws Exception;

	/**
	 * 校验验证码信息
	 * @param servletWebRequest
	 */
	void validate(ServletWebRequest servletWebRequest);
}
