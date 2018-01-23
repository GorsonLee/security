package com.gorson.securitybrowser.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gorson.securitybrowser.BrowserSecurityConfig;
import com.gorson.securitycore.properties.BrowserProperties;
import com.gorson.securitycore.properties.LoginType;
import com.gorson.securitycore.properties.SecurityCoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 继承默认的登陆完毕的处理器
 */
@Component("gorsonAuthenticationSuccessHandlerSelector")
public class GorsonAuthenticationSuccessHandlerSelector extends SavedRequestAwareAuthenticationSuccessHandler {
    private Logger logger = LoggerFactory.getLogger(GorsonAuthenticationSuccessHandlerSelector.class);

    @Resource
    private ObjectMapper objectMapper;
    @Resource
    private SecurityCoreProperties securityCoreProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        logger.info("登陆成功");

        if (LoginType.JSON.equals(securityCoreProperties.getBrowser().getLoginType())) {
            httpServletResponse.setContentType("application/json;charset=UTF-8");
            httpServletResponse.getWriter().write(objectMapper.writeValueAsString(authentication));
        } else {
            super.onAuthenticationSuccess(httpServletRequest, httpServletResponse, authentication);
        }
    }
}
