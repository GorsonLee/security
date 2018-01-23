package com.gorson.securitybrowser;

import com.gorson.securitybrowser.support.SimpleResponse;
import com.gorson.securitycore.properties.SecurityCoreProperties;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 对请求进行分类的控制器
 */
@RestController
public class BrowserSecurityController {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);

    private RequestCache requestCache = new HttpSessionRequestCache(); //缓存重定向前的请求
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy(); //重定向跳转

    @Resource
    private SecurityCoreProperties securityCoreProperties;

    /**
     * 当需要身份验证时，跳转到这里
     *
     * @param request
     * @param response
     * @return
     */
    @GetMapping("/authentication/require")
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    public SimpleResponse requireAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {
            String target = savedRequest.getRedirectUrl(); //获取重定向的Url

            //如果引发跳转页面是html，则跳转到登陆页面，否则返回Json字符串
            if (StringUtils.endsWithIgnoreCase(target, ".html")) {
                redirectStrategy.sendRedirect(request,
                        response,
                        securityCoreProperties.getBrowser().getLoginPage());
            }
        }

        return new SimpleResponse("需要身份认证，请引导到登陆页面");
    }
}
