package com.gorson.securitycore.validate.code;

import com.gorson.securitycore.Constants;
import com.gorson.securitycore.exception.ValidateCodeException;
import com.gorson.securitycore.properties.SecurityCoreProperties;
import com.gorson.securitycore.validate.code.model.ValidateCodeType;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 拦截验证码的校验
 */
@Component("validateCodeFilter")
public class ValidateCodeFilter extends OncePerRequestFilter implements InitializingBean {
    private Logger logger = LoggerFactory.getLogger(ValidateCodeFilter.class);

    @Resource
    private AuthenticationFailureHandler gorsonAuthenticationFailureHandlerSelector;
    @Resource
    private SecurityCoreProperties securityCoreProperties;
    @Resource
    private ValidateCodeProcessorHolder validateCodeProcessorHolder;

    private AntPathMatcher pathMatcher = new AntPathMatcher();
    private Map<String, ValidateCodeType> urlMap = new HashMap<>();

    /**
     * 在Bean初始化完之后，初始化局部变量
     * @throws ServletException
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();

        urlMap.put(Constants.LOGIN_URL_FORM, ValidateCodeType.IMAGE);
        addUrlToMap(securityCoreProperties.getCode().getImage().getUrl(), ValidateCodeType.IMAGE);

        urlMap.put(Constants.LOGIN_URL_MOBILE, ValidateCodeType.SMS);
        addUrlToMap(securityCoreProperties.getCode().getSms().getUrl(), ValidateCodeType.SMS);
    }

    private void addUrlToMap(String urlString, ValidateCodeType type) {
        if (StringUtils.isNotBlank(urlString)) {
            String[] urls = StringUtils.splitByWholeSeparatorPreserveAllTokens(urlString, ",");
            for (String url : urls) {
                urlMap.put(url, type);
            }
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        ValidateCodeType type = getValidateCodeType(httpServletRequest);

        //处理认证请求，将图片校验逻辑添加到这里
        if (type != null) {
            logger.info("拦截的请求: " + type.getParamNameOnValidate() + " " + httpServletRequest.getRequestURI());

            try {
                logger.info("拦截的请求: 开始验证验证码！");
                validateCodeProcessorHolder.getValidateCodeGenerator(type).validate(new ServletWebRequest(httpServletRequest));
            } catch (ValidateCodeException e) {
                gorsonAuthenticationFailureHandlerSelector.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
                return;
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private ValidateCodeType getValidateCodeType(HttpServletRequest request) {
        ValidateCodeType result = null;
        if (!StringUtils.equalsIgnoreCase(request.getMethod(), "get")) {
            Set<String> urls = urlMap.keySet();
            for (String url : urls) {
                if (pathMatcher.match(url, request.getRequestURI())) {
                    result = urlMap.get(url);
                }
            }
        }

        return result;
    }
}
