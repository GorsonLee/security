
# SpringSecurity的原理
使用SpringSecurity进行登陆验证，就是将登陆信息通过一系列的过滤器处理，可以使用security.basic.enabled=false禁用。步骤如下：

请求 --- UsernamePasswordAuthenticationFilter --- BasicAuthenticationFilter --- ... --- ExcecptionTranslationFilter --- FilterSecurityInterceptor --- Rest Api

定义Form登陆的示例，并配置账户密码，内容包含：
* 处理用户信息获取逻辑（UserDetailsService）：查询数据库
* 处理用户校验逻辑（UserDetails）：四参数或者七参数构造函数
* 处理密码加密解密（PasswordEncoder）：在存储之前使用加密算法处理

```java
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("Browser Security Config");
        http.formLogin() //表单登陆，指定身份认证的方式，HttpBasic登陆方式：http.httpBasic()
                .and()
                .authorizeRequests() //授权配置
                .anyRequest() //任何请求
                .authenticated(); //都需要身份认证
    }
}

//声明组建用于用户登陆的身份验证
@Component
public class MyUserDetailService implements UserDetailsService {
    private Logger logger = LoggerFactory.getLogger(MyUserDetailService.class);

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        //根据用户名数据库查询信息
        logger.info("用户登陆");
//        return new User(userName, "123456",  AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));

        //根据数据库查询到的信息，对账户进行更加精细的设置，例如是否过期，冻结等等，调用User的七个参数构造函数实现
        return new User(userName,
                "123456",
                true,
                true,
                true,
                false,
         AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
```

使用Spring的加密算法，在存储到数据库之前，将用户的密码加密。最后返回User时，密码为加密后的数据：
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

# 自定义登陆页面
## 示例一：自定义登陆页面
```java
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("Browser Security Config");
        http.formLogin() //表单登陆，指定身份认证的方式
                .loginPage("/login.html") //自定登陆的链接
                .loginProcessingUrl("/authentication/form") //指定处理的登陆事件Action
                .and()
                .authorizeRequests() //授权配置
                .antMatchers("/login.html").permitAll() //授权登陆界面
                .anyRequest() //任何请求
                .authenticated() //都需要身份认证
                .and()
                .csrf().disable(); //禁用csrf防护
    }
}
```
```html
<!--login.html-->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>登录</title>
</head>
<body>
<h2>标准登录页面</h2>
<h3>表单登录</h3>
<form action="/authentication/form" method="post">
    <table>
        <tr>
            <td>用户名:</td>
            <td><input type="text" name="username"></td>
        </tr>
        <tr>
            <td>密码:</td>
            <td><input type="password" name="password"></td>
        </tr>
        <tr>
            <td colspan="2"><button type="submit">登录</button></td>
        </tr>
    </table>
</form>
</body>
</html>
```

## 示例二：请求进行分类，引导登陆，模型如下：
假如存在需求，只对浏览器访问的.html页面需要身份验证时，对其他请求返回别的信息，此时需要对请求进行分类处理。

密码验证的代码见上面MyUserDetailService.java。
下面是身份验证的链接，用于对请求进行判断分类：
```java
@RestController
public class BrowserSecurityController {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);
    private RequestCache requestCache = new HttpSessionRequestCache(); //缓存重定向前的请求
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy(); //重定向跳转

    @Resource
    private SecurityCoreProperties securityCoreProperties;

    @GetMapping("/authentication/require")
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED) //返回的错误码
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

        return new SimpleResponse("需要身份认证，请引导到登陆页面"); //返回的对象
    }
}

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);

    @Resource
    private SecurityCoreProperties securityCoreProperties;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() //表单登陆，指定身份认证的方式
                .loginPage("/authentication/require") //跳转到是否需要身份验证，在验证授权的界面实现页面的跳转
                .and()
                .authorizeRequests() //授权配置
                .antMatchers("/authentication/require", securityCoreProperties.getBrowser().getLoginPage()).permitAll() //授权登陆界面
                .anyRequest() //任何请求
                .authenticated() //都需要身份认证
                .and()
                .csrf().disable(); //禁用csrf防护
    }
}
```

属性配置：application.property中配置登陆的链接：
gorson.security.browser.loginPage=/login.html

```java
@Configuration
@EnableConfigurationProperties(SecurityCoreProperties.class)
public class SecurityCoreConfig {
}

@ConfigurationProperties(prefix = "gorson.security")
public class SecurityCoreProperties {
    private BrowserProperties browser = new BrowserProperties(); //注意变量的名称需要和application.property的属性保持一致

    public BrowserProperties getBrowser() {
        return browser;
    }

    public void setBrowser(BrowserProperties browser) {
        this.browser = browser;
    }

}

public class BrowserProperties {
    private String loginPage = "/demo-signIn.html";

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }
}
```

# 登陆成功和失败的返回
Spring默认返回之前的页面进行跳转。
自定义可以通过实现AuthenticationSuccessHandler和AuthenticationFailureHandler接口，然后配置到WebSecurityConfigurerAdapter：
```java
@Component("gorsonAuthenticationSuccessHandler")
public class GorsonAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private Logger logger = LoggerFactory.getLogger(GorsonAuthenticationSuccessHandler.class);

    @Resource
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        logger.info("登陆成功");
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(authentication));
    }
}

@Component("gorsonAuthenticationFailureHandler")
public class GorsonAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private Logger logger = LoggerFactory.getLogger(GorsonAuthenticationFailureHandler.class);

    @Resource
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        logger.info("登陆失败");
        httpServletResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(e));
    }
}

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger logger = LoggerFactory.getLogger(BrowserSecurityConfig.class);

    @Resource
    private SecurityCoreProperties securityCoreProperties;
    @Resource
    private AuthenticationSuccessHandler gorsonAuthenticationSuccessHandler;
    @Resource
    private AuthenticationFailureHandler gorsonAuthenticationFailureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("Browser Security Config");
        http.formLogin() //表单登陆，指定身份认证的方式
                .loginPage("/authentication/require") //是否需要身份验证
                .loginProcessingUrl("/authentication/form") //指定登陆的Action
                .successHandler(gorsonAuthenticationSuccessHandler) //登陆成功的处理
                .failureHandler(gorsonAuthenticationFailureHandler) //登陆失败的处理
                .and()
                .authorizeRequests() //授权配置
                .antMatchers("/authentication/require", securityCoreProperties.getBrowser().getLoginPage()).permitAll() //授权登陆界面
                .anyRequest() //任何请求
                .authenticated() //都需要身份认证
                .and()
                .csrf().disable(); //禁用csrf防护
    }
}
```

兼容默认的登陆验证后跳转处理器：通过gorson.security.browser.loginType=REDIRECT配置

```java
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
```

# 图片验证码
## 1.生成图形验证码接口
步骤：根据随机数生成图形，将随机数存到Session中，将生成的图片写到接口的响应中。
```java
@RestController
public class ValidateCodeController {
    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @GetMapping("/code/image")
    public void createCode(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //TODO 生成验证码存放在ImageCode类对象中，ImageCode的参数：BufferImage image，String code， LocalDateTime expireTime
        sessionStrategy.setAttribute(new ServletWebRequest(request), Constants.SESSION_KEY, imageCode); //将验证码信息存放在Session
        ImageIO.write(imageCode.getImage(), "JPEG", response.getOutputStream()); //响应验证码的图片
    }
}
```

## 2.图形验证码校验：实现原理是在UsernamePasswordAnthenticationFilter的前面添加自定义的过滤器。
实现的编码如下：
```java
public class ValidateCodeFilter extends OncePerRequestFilter {
    private Logger logger = LoggerFactory.getLogger(ValidateCodeFilter.class);

    private AuthenticationFailureHandler authenticationFailureHandler;
    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        logger.info("拦截的请求: " + httpServletRequest.getRequestURL());

        //处理认证请求，将图片校验逻辑添加到这里
        if (StringUtils.equals("/authentication/form", httpServletRequest.getRequestURI())
                && StringUtils.equalsIgnoreCase(httpServletRequest.getMethod(), "post")) {
            try {
                validate(new ServletWebRequest(httpServletRequest));
            } catch (ValidateCodeException e) {
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
                return;
            }

        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void validate(ServletWebRequest request) throws ServletRequestBindingException {
        ImageCode codeInSession = (ImageCode) sessionStrategy.getAttribute(request, Constants.SESSION_KEY);

        //根字段获取表单提交的输入信息
        String codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(), "imageCode");

        if (codeInSession == null) {
            throw new ValidateCodeException("验证码不存在");
        }

        if (codeInSession.isExpired()) {
            sessionStrategy.removeAttribute(request, Constants.SESSION_KEY);
            throw new ValidateCodeException("验证码已过期");
        }

        if (!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
            throw new ValidateCodeException("验证码不匹配");
        }

        sessionStrategy.removeAttribute(request, Constants.SESSION_KEY);
    }

    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    public void setSessionStrategy(SessionStrategy sessionStrategy) {
        this.sessionStrategy = sessionStrategy;
    }
}
```

然后配置到登陆配置中：
```java
protected void configure(HttpSecurity http) throws Exception {
    ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
    validateCodeFilter.setAuthenticationFailureHandler(gorsonAuthenticationFailureHandlerSelector);
    http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) //将拦截器添加在身份验证的前面
            .formLogin() //表单登陆，指定身份认证的方式
            .loginPage("/authentication/require") //是否需要身份验证
            .loginProcessingUrl("/authentication/form") //指定登陆的Action
            .successHandler(gorsonAuthenticationSuccessHandlerSelector) //登陆成功的处理
            .failureHandler(gorsonAuthenticationFailureHandlerSelector) //登陆失败的处理
            .and()
            .authorizeRequests() //授权配置
            .antMatchers("/authentication/require",
                    securityCoreProperties.getBrowser().getLoginPage(), "/code/image").permitAll() //授权登陆界面
            .anyRequest() //任何请求
            .authenticated() //都需要身份认证
            .and()
            .csrf().disable(); //禁用csrf防护
}
```

可重用代码的优化思路：
* 验证码基本参数：默认配置-》应用级配置-》请求级配置
ServletRequestUtils.getIntParameter从请求中获取参数，如果获取不到则赋值默认值。
```java
int width = ServletRequestUtils.getIntParameter(request.getRequest(), "width", securityCoreProperties.getCode().getImage().getWidth());
int height = ServletRequestUtils.getIntParameter(request.getRequest(), "height", securityCoreProperties.getCode().getImage().getHeight());
```

* 验证码拦截的接口配置；
```java
public class ValidateCodeFilter extends OncePerRequestFilter implements InitializingBean {
    private Logger logger = LoggerFactory.getLogger(ValidateCodeFilter.class);

    private AuthenticationFailureHandler authenticationFailureHandler;
    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();
    private Set<String> uris = new HashSet<>();
    private SecurityCoreProperties securityCoreProperties;
    private AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * 在Bean初始化完之后，调用该方法初始化局部变量
     * @throws ServletException
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        String[] configUrls = StringUtils.splitByWholeSeparatorPreserveAllTokens(securityCoreProperties.getCode().getImage().getUrl(), ",");
        uris.addAll(Arrays.asList(configUrls));
        uris.add("/authentication/form");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String requestUri = httpServletRequest.getRequestURI();
        logger.info("拦截的请求: " + httpServletRequest.getRequestURI());
        
        //遍历验证是否需要验证码校验
        boolean action = uris.stream().anyMatch(uri -> pathMatcher.match(uri, requestUri));

        //处理认证请求，将图片校验逻辑添加到这里
        if (action) {
            try {
                logger.info("拦截的请求: 开始验证验证码！");
                validate(new ServletWebRequest(httpServletRequest));
            } catch (ValidateCodeException e) {
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, e);
                return;
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void validate(ServletWebRequest request) throws ServletRequestBindingException {
        ...
    }

    getter，setter {... }  

}

@Override
protected void configure(HttpSecurity http) throws Exception {
    logger.info("Browser Security Config");
    ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
    validateCodeFilter.setAuthenticationFailureHandler(gorsonAuthenticationFailureHandlerSelector);
    validateCodeFilter.setSecurityCoreProperties(securityCoreProperties);
    validateCodeFilter.afterPropertiesSet();

    http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
            .formLogin() //表单登陆，指定身份认证的方式
            .loginPage("/authentication/require") //是否需要身份验证
            .loginProcessingUrl("/authentication/form") //指定登陆的Action
            .successHandler(gorsonAuthenticationSuccessHandlerSelector) //登陆成功的处理
            .failureHandler(gorsonAuthenticationFailureHandlerSelector) //登陆失败的处理
            .and()
            .authorizeRequests() //授权配置
            .antMatchers("/authentication/require",
                    securityCoreProperties.getBrowser().getLoginPage(), "/code/image").permitAll() //授权登陆界面
            .anyRequest() //任何请求
            .authenticated() //都需要身份认证
            .and()
            .csrf().disable(); //禁用csrf防护
}
```

在application.property中配置：gorson.security.code.image.url=/user/getUser/*

* 验证码的生成逻辑：将验证码生成逻辑封装成一个Bean，当Bean不存在的时候，配置MissingBean：
```java
@Configuration
public class ValidateCodeBeanConfig {
   
   @Resource
   private SecurityCoreProperties securityCoreProperties;
   
   @Bean
   @ConditionalOnMissingBean(name = "imageValidateCodeGenerator")
   public ValidateCodeGenerator imageCodeGenerator() {
      ImageCodeGenerator imageCodeGenerator = new ImageCodeGenerator();
      imageCodeGenerator.setSecurityCoreProperties(securityCoreProperties);
      return imageCodeGenerator;
   }
}

//在应用层定义同名字的Component：
@Component("imageValidateCodeGenerator")
public class DemoImageCodeGenerator implements ValidateCodeGenerator {
    @Override
    public ValidateCode generate(ServletWebRequest request) {
        System.out.println("应用级的验证码生成器");
        return null;
    }
}
```
