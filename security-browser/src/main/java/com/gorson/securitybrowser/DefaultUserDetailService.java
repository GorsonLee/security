package com.gorson.securitybrowser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * 用户账户密码验证的Bean
 */
@Component
public class DefaultUserDetailService implements UserDetailsService {
    private Logger logger = LoggerFactory.getLogger(DefaultUserDetailService.class);

    @Resource
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        //根据用户名数据库查询信息
        logger.info("用户登陆");
//        return new User(userName, "123456", AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));

        //根据数据库查询到的信息，对账户进行更加精细的设置，例如是否过期，冻结等等，调用User的七个参数构造函数实现
        return new User(userName,
                passwordEncoder.encode("123456"),
                true,
                true,
                true,
                true,
                AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
