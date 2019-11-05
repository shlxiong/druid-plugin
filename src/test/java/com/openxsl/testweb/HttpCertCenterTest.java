package com.openxsl.testweb;

import java.util.Properties;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.Assert;

import com.alibaba.druid.pool.PasswordManager;
import com.alibaba.druid.pool.PasswordManager.CC;
import com.openxsl.config.DruidHttpCertCenter;
import com.openxsl.config.testuse.AutoConfig;
import com.openxsl.config.testuse.BasicTest;
import com.openxsl.config.util.BeanUtils;

@AutoConfig(application="springboot-test")
@ContextConfiguration(locations="classpath*:spring/dal/http-client.xml")
@TestPropertySource(
		properties= {"spring.component.scanpackage=com.alibaba.druid"}
	)
public class HttpCertCenterTest extends BasicTest {
	@Autowired
	private DruidHttpCertCenter cc;

	@Test
	public void test() throws Exception {
		String environ = "DEV";
		String certId = "1486774364352717";
//		PublicKey pubKey = cc.getPublicKey(environ, certId);
//		PrivateKey privKey = cc.getPrivateKey(environ, certId);
		
		System.setProperty("spring.profiles.active", environ);
		System.setProperty("druid.debug", "true");
		
		PasswordManager manager = new PasswordManager();
		Object callback = BeanUtils.getPrivateField(manager, "passwordCallback");
		setCC(callback, cc);
		String plainText = "root";
		//callback.encrypt("root", certId)
		String encoded = (String)invoke(callback, "encrypt", plainText,certId);
		System.out.println(encoded);
		//callback.decrypt(encoded, certId);
		String password = (String)invoke(callback, "decrypt", encoded, certId); 
		System.out.println(password);
		Assert.isTrue(!plainText.equals(encoded) && plainText.equals(password),
					"加/解密失败，请确认证书是否存在");
		
		Properties properties = new Properties();
		properties.setProperty("password", encoded);
		properties.setProperty(PasswordManager.ENCRYPT_CERT, certId);
//		
//		DruidDataSource dataSource = new DruidDataSource();
//		dataSource.setConnectProperties(properties);
//		manager.decryptIfNecessary(properties, dataSource);
	}
	
	private Object invoke(Object bean, String method, Object... args) throws Exception{
		java.lang.reflect.Method invoker = bean.getClass().getDeclaredMethod(method, String.class,String.class);
		invoker.setAccessible(true);
		return invoker.invoke(bean, args);
	}
	private Object setCC(Object bean, CC cc) throws Exception{
		java.lang.reflect.Method invoker = bean.getClass().getDeclaredMethod("setCC", CC.class);
		invoker.setAccessible(true);
		return invoker.invoke(bean, cc);
	}
}
