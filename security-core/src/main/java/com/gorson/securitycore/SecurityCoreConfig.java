package com.gorson.securitycore;

import com.gorson.securitycore.properties.SecurityCoreProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SecurityCoreProperties.class)
public class SecurityCoreConfig {
}
