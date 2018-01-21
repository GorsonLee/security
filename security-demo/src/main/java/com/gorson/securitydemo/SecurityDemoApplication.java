package com.gorson.securitydemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.concurrent.locks.Condition;

@SpringBootApplication
@EnableSwagger2
public class SecurityDemoApplication {
	public static void main(String[] args) {
		SpringApplication.run(SecurityDemoApplication.class, args);
	}
}
