package com.openxsl.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.alibaba.druid.filter.PasswordFilter;
import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.pool.PasswordManager;
import com.openxsl.config.autodetect.ScanConfig;

@Configuration
@ScanConfig
public class DruidConfiguration {
	static PasswordFilter filter = null;
	
	@Bean
	public PasswordManager druidPasswordMgr(DruidDataSource dataSource) {
		PasswordManager manager = new PasswordManager();
		filter = new PasswordFilter();
		filter.setPasswordMgr(manager);
		return manager;
	}

}
