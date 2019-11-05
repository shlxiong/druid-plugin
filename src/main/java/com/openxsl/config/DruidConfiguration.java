package com.openxsl.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.alibaba.druid.pool.PasswordManager;

@Configuration
public class DruidConfiguration {
	
	@Bean
	public PasswordManager druidPasswordMgr() {
		return new PasswordManager();
	}

}
