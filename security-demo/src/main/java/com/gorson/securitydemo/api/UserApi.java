package com.gorson.securitydemo.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserApi {
    @GetMapping("/getUser")
    public String getUser() {
        return "xxx";
    }

}
