package com.test;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication

@RestController
public class LoginApplication {
	private Logger logger = LoggerFactory.getLogger(LoginApplication.class);
	@RequestMapping("/user")
	public Principal user(Principal principal){
		logger.info("Come");
		return principal;
	}
	
	public static void main(String[] args) {
		SpringApplication.run(LoginApplication.class, args);
	}
}
