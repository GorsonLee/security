package com.gorson.securitycore.validate.code.sms;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultSmsCodeSender implements SmsCodeSender {
	private Logger logger = LoggerFactory.getLogger(DefaultSmsCodeSender.class);

	@Override
	public void send(String mobile, String code) {
		logger.info(mobile + "的验证码为：" + code);
	}
}
