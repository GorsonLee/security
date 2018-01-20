package com.gorson.securitydemo;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.Resource;
import javax.annotation.Resources;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SecurityDemoApplicationTests {
    @Resource
    private WebApplicationContext mContext;
    private MockMvc mMockMvc;

    @Before
    public void init() {
    }
}
