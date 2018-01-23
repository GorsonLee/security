package com.gorson.securitybrowser.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gorson.securitycore.properties.LoginType;
import com.gorson.securitycore.properties.SecurityCoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component("gorsonAuthenticationFailureHandlerSelector")
public class GorsonAuthenticationFailureHandlerSelector extends SimpleUrlAuthenticationFailureHandler {
    private Logger logger = LoggerFactory.getLogger(GorsonAuthenticationFailureHandlerSelector.class);

    @Resource
    private ObjectMapper objectMapper;
    @Resource
    private SecurityCoreProperties securityCoreProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        logger.info("登陆失败");

        if (LoginType.JSON.equals(securityCoreProperties.getBrowser().getLoginType())) {
            httpServletResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            httpServletResponse.setContentType("application/json;charset=UTF-8");
            httpServletResponse.getWriter().write(objectMapper.writeValueAsString(e));
        } else {
            super.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
        }
    }
}
