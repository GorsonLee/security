package com.gorson.securitycore.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gorson.security")
public class SecurityCoreProperties {
    private BrowserProperties browser = new BrowserProperties(); //登陆属性

    private ValidateCodeProperties code = new ValidateCodeProperties(); //图片和短信的验证属性

    private SocialProperties social = new SocialProperties(); //社交属性

    public BrowserProperties getBrowser() {
        return browser;
    }

    public void setBrowser(BrowserProperties browser) {
        this.browser = browser;
    }

    public ValidateCodeProperties getCode() {
        return code;
    }

    public void setCode(ValidateCodeProperties code) {
        this.code = code;
    }

    public SocialProperties getSocial() {
        return social;
    }

    public void setSocial(SocialProperties social) {
        this.social = social;
    }
}
