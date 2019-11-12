package com.openxsl.config;

import java.sql.SQLException;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import com.alibaba.druid.filter.Filter;
import com.alibaba.druid.pool.DruidDataSource;
import com.openxsl.config.util.BeanUtils;

/**
 * 拦截DruidDataSource的初始化，等待PasswordFilter后再初始化
 * 
 * @author xiongsl
 */
@Component
public class DruidInitiationPostProcessor implements BeanPostProcessor{
	
	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		if (bean instanceof DruidDataSource) {
			DruidDataSource dataSource = (DruidDataSource)bean;
			BeanUtils.setPrivateField(dataSource, "inited", true);
			new DataSourceLazyInitiator(dataSource).start();
		} 
		return bean;
	}

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}
	
	class DataSourceLazyInitiator extends Thread {
		DruidDataSource dataSource;
		
		public DataSourceLazyInitiator(DruidDataSource dataSource) {
			this.dataSource = dataSource;
		}
		
		public void run() {
			Filter filter = null;
			while ((filter=DruidConfiguration.filter) == null) {
				try {
					Thread.sleep(10);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			
			dataSource.getProxyFilters().add(filter);
			BeanUtils.setPrivateField(dataSource, "inited", false);
			try {
				dataSource.init();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		
	}

}
