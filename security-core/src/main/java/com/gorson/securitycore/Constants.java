package com.gorson.securitycore;

public class Constants {
    public static final String MOBILE_PARAM = "mobile";
    public static final String DEFAULT_PARAMETER_NAME_CODE_IMAGE = "imageCode"; //图片验证码的请求字段
    public static final String DEFAULT_PARAMETER_NAME_CODE_SMS = "smsCode"; //短信验证码的请求字段

    public static final String SESSION_KEY_PREFIX = "SESSION_KEY_FOR_CODE_"; //存储验证码信息实体的名称前缀

    public static final String VALIDATE_CODE_URL_PREFIX = "/code"; //验证码获取的请求链接前缀
    public static final String LOGIN_URL_FORM = "/authentication/form"; //表单格式身份验证的链接
    public static final String LOGIN_URL_MOBILE = "/authentication/mobile"; //短信身份验证的链接
    public static final String LOGIN_URL_REQUIRE = "/authentication/require"; //跳转身份验证的链接

}
