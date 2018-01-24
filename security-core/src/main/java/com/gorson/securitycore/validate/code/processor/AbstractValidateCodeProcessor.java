package com.gorson.securitycore.validate.code.processor;

import com.gorson.securitycore.Constants;
import com.gorson.securitycore.exception.ValidateCodeException;
import com.gorson.securitycore.validate.code.model.ValidateCode;
import com.gorson.securitycore.validate.code.model.ValidateCodeGenerator;
import com.gorson.securitycore.validate.code.model.ValidateCodeType;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Map;

public abstract class AbstractValidateCodeProcessor<C extends ValidateCode> implements ValidateCodeProcessor {
	private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

	@Autowired
	private Map<String, ValidateCodeGenerator> validateCodeGenerators;

	@Override
	public void create(ServletWebRequest request) throws Exception {
		C validateCode = generate(request); //生成验证码
		save(request, validateCode); //将验证码存储到客户端Session
		send(request, validateCode); //将验证码发送到客户端
	}

	/**
	 * 根据生成器的Bean名字在Map中获取相应的Bean，生成响应的验证码
	 *
	 * @param request
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private C generate(ServletWebRequest request) {
		String type = getValidateCodeType(request).toString().toLowerCase(); //获取验证码的名称，例如sms，image
		String generatorName = type + ValidateCodeGenerator.class.getSimpleName(); //拼接生成器的名字
		ValidateCodeGenerator validateCodeGenerator = validateCodeGenerators.get(generatorName); //获取生成器

		if (validateCodeGenerator == null) {
			throw new ValidateCodeException("验证码生成器" + generatorName + "不存在");
		}

		return (C) validateCodeGenerator.generate(request); //调用生成器的生成验证码方法
	}

	/**
	 * 保将验证码信息存储到Session中
	 *
	 * @param request
	 * @param validateCode
	 */
	private void save(ServletWebRequest request, C validateCode) {
		sessionStrategy.setAttribute(request, getSessionKey(request), validateCode);
	}

	/**
	 * 发送校验码，由子类实现
	 *
	 * @param request
	 * @param validateCode
	 * @throws Exception
	 */
	protected abstract void send(ServletWebRequest request, C validateCode) throws Exception;

	/**
	 * 根据请求的url获取校验码的类型
	 *
	 * @param request
	 * @return
	 */
	private ValidateCodeType getValidateCodeType(ServletWebRequest request) {
		String type = StringUtils.substringBefore(getClass().getSimpleName(), "CodeProcessor");
		return ValidateCodeType.valueOf(type.toUpperCase());
	}

	/**
	 * 构建验证码放入session时的key
	 *
	 * @param request
	 * @return
	 */
	private String getSessionKey(ServletWebRequest request) {
		return Constants.SESSION_KEY_PREFIX + getValidateCodeType(request).toString().toUpperCase();
	}

	@SuppressWarnings("unchecked")
	@Override
	public void validate(ServletWebRequest request) {
		ValidateCodeType processorType = getValidateCodeType(request); //获取验证类型
		String sessionKey = getSessionKey(request); //获取Session Key
		C codeInSession = (C) sessionStrategy.getAttribute(request, sessionKey); //得到完整的验证码信息

		String codeInRequest; //提交的信息
		try {
			//根据字段获取表单提交的输入信息
			codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(),
					processorType.getParamNameOnValidate());
		} catch (ServletRequestBindingException e) {
			throw new ValidateCodeException("获取验证码的值失败");
		}

		if (StringUtils.isBlank(codeInRequest)) {
			throw new ValidateCodeException(processorType + "验证码的值不能为空");
		}

		if (codeInSession == null) {
			throw new ValidateCodeException(processorType + "验证码不存在");
		}

		if (codeInSession.isExpired()) {
			sessionStrategy.removeAttribute(request, sessionKey);
			throw new ValidateCodeException(processorType + "验证码已过期");
		}

		if (!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
			throw new ValidateCodeException(processorType + "验证码不匹配");
		}

		sessionStrategy.removeAttribute(request, sessionKey);
	}

}
