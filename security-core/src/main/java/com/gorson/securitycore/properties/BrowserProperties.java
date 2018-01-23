package com.gorson.securitycore.properties;

public class BrowserProperties {
    private String loginPage = "/demo-signIn.html"; //默认的登陆页面

    private LoginType loginType = LoginType.JSON; //登陆处理返回的格式

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public LoginType getLoginType() {
        return loginType;
    }

    public void setLoginType(LoginType loginType) {
        this.loginType = loginType;
    }
}
