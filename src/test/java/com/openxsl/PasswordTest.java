package com.openxsl;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.Assert;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.pool.PasswordManager;
import com.alibaba.druid.pool.PasswordManager.CC;

import junit.framework.TestCase;

public class PasswordTest extends TestCase{
	private DruidDataSource ds1;
//	private DruidDataSource ds2;

	@Override
	protected void setUp() throws Exception {
//		String text = "ClassPathXmlApplicationContext";
//		byte[] bytes = this.exchange(text.getBytes());
//		System.out.println(new String(bytes));
//		bytes = this.exchange(bytes);
//		System.out.println(text);
		
		ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext("classpath:druid.xml");
		ds1 = ctx.getBean("dataSource", DruidDataSource.class);
//		ds2 = ctx.getBean("dataSourceNonfilters", DruidDataSource.class);
//		ctx.close();
	}
	
	public void test() throws Exception{
		if (ds1 == null) {
			return;
		}
//		System.out.println(ConfigTools.encrypt("123456"));
		System.out.println("password: "+ds1.getPassword());
		System.out.println("connectProps1====="+ds1.getConnectProperties());
		System.out.println("connectionObj====="+ds1.getConnection());
//		System.out.println("connectProps2====="+ds1.getConnectProperties());
//		System.out.println(ds2.getPassword());
		
		//通过反射调用 SumpayPasswodCallback.decrypt(String,String)
		PasswordManager manager = new PasswordManager();
		Field field = manager.getClass().getDeclaredField("passwordCallback");
		field.setAccessible(true);
		Object callback = field.get(manager);
		Method method = callback.getClass().getDeclaredMethod("setCC", CC.class);
		method.setAccessible(true);
		method.invoke(callback, manager.getCC());
		
		//不允许直接调 callback.decrypt(String, String)
		method = callback.getClass().getDeclaredMethod("decrypt", String.class,String.class);
		method.setAccessible(true);
		Object str = method.invoke(callback, "Y30PP7vwVzbDe7HtVvX6B7EbTU9dqeVY","tomcat-1.0");
		Assert.assertEquals("Error", str);
	}
	
	private final byte[] exchange(byte[] data) {
		final int len = data.length;
		for (int i=0,j=i+2; j<len; i+=3,j+=3) {
			byte tmp = data[i];
			data[i] = data[j];
			data[j] = tmp;
		}
		int j = len-3 - len%3;
		for (int i=0; i<j; j-=3) {
			for (int k=0; k<3; i++,k++) {
				byte tmp = data[i];
				data[i] = data[j+k];
				data[j+k] = tmp;
			}
		}
		return data;
	}

}
