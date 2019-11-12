package com.openxsl.config;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.alibaba.druid.pool.DruidConfigTool;
import com.alibaba.druid.pool.PasswordManager.CC;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.openxsl.config.condition.ConditionalOnPresent;

/**
 * 从远程文件服务器（证书中心）获取证书公私钥
 * 
 * @author xiongsl
 */
@Component
@ConditionalOnPresent(properties="spring.jdbc.druid.cert.server")
public class DruidHttpCertCenter implements CC {
	private final Logger logger = LoggerFactory.getLogger(getClass());
	@Autowired
	private RestInvoker httpClient;
	@Value("${jdbc.druid.cert.server}")
	private String serverUrl;
	private String token;        //访问凭证
	
	/**
	 * 生成一个证书，保存到环境中(environ)
	 */
	@Override
	public String generCert(String environ, String certId, String storePass) throws IOException {
//		String url = String.format("%s/cert/generate/%s/%s/%s", serverUrl,environ,certId,storePass);
		//httpClient.postForm(url);
		return null;
	}

	/**
	 * 加载环境中(environ)的所有的公私钥证书
	 * @throws IOException 
	 * @see PasswordManager
	 */
	@Override
	public void listSecureKeys(String environ, Map<String, PublicKey> publicKeyMap,
							Map<String, PrivateKey> privateKeyMap) throws IOException {
		String url = String.format("%s/cert/list/%s", serverUrl, environ);
		String response = httpClient.get(url, null, "application/json", String.class);
		if (response==null || "".equals(response)) {
			logger.warn("There is no secure keys found, maybe server has broken down");
		}
		JSONObject map = JSON.parseObject(response);
		JSONObject privateKeys = JSON.parseObject(map.get("private").toString());
		privateKeyMap.clear();
		for (Map.Entry<String,?> entry : privateKeys.entrySet()) {
			try {
				byte[] keyData = DruidConfigTool.decryptBlock(entry.getValue().toString());
				privateKeyMap.put(entry.getKey(), DruidConfigTool.getPrivateKey(keyData));
			} catch(Exception e) {
				throw new IOException(e);
			}
		}
		
		JSONObject publicKeys = JSON.parseObject(map.get("public").toString());
		publicKeyMap.clear();
		for (Map.Entry<String,?> entry : publicKeys.entrySet()) {
			try {
				byte[] keyData = DruidConfigTool.decryptBlock(entry.getValue().toString());
				publicKeyMap.put(entry.getKey(), DruidConfigTool.getPublicKey(keyData));
			} catch(Exception e) {
				throw new IOException(e);
			}
		}
		logger.info("[{}] loaded publicKeys: {}, privateKeys: {}", environ,
					publicKeyMap.keySet(), privateKeyMap.keySet());
	}

	@Override
	public PublicKey getPublicKey(String environ, String certId) throws IOException {
		String url = String.format("%s/cert/publickey/%s/%s?%s", serverUrl,environ,
									certId, this.getToken());
		String response = httpClient.get(url, null, "application/json", String.class);
		try {
			byte[] keyData = DruidConfigTool.decryptBlock(response);
			return DruidConfigTool.getPublicKey(keyData);
		} catch(Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public PrivateKey getPrivateKey(String environ, String certId) throws IOException {
		String url = String.format("%s/cert/privatekey/%s/%s?%s", serverUrl,environ,
								 	certId, this.getToken());
		String response = httpClient.get(url, null, "application/json", String.class);
		try {
			byte[] keyData = DruidConfigTool.decryptBlock(response);
			return DruidConfigTool.getPrivateKey(keyData);
		} catch(Exception e) {
			throw new IOException(e);
		}
	}
	
	@Override
	public void setToken(String token){
		this.token = token;
	}
	private String getToken() {
		return this.token;
	}
	
	public void setServerUrl(String url) {
		this.serverUrl = url;
	}
	
}
