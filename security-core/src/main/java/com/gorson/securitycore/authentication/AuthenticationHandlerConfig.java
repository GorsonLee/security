package com.gorson.securitycore.authentication;

import com.gorson.securitycore.authentication.handler.GorsonAuthenticationFailureHandlerSelector;
import com.gorson.securitycore.authentication.handler.GorsonAuthenticationSuccessHandlerSelector;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class AuthenticationHandlerConfig {
    @Bean
    @ConditionalOnMissingBean(AuthenticationSuccessHandler.class)
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new GorsonAuthenticationSuccessHandlerSelector();
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationFailureHandler.class)
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new GorsonAuthenticationFailureHandlerSelector();
    }
}
