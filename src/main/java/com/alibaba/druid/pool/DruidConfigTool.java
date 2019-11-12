package com.alibaba.druid.pool;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.alibaba.druid.filter.config.ConfigTools;
import com.alibaba.druid.util.Base64;

public class DruidConfigTool extends ConfigTools {
	private static final String DEFAULT_PRIVATE_KEY_STRING = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAocbCrurZGbC5GArEHKlAfDSZi7gFBnd4yxOt0rwTqKBFzGyhtQLu5PRKjEiOXVa95aeIIBJ6OhC2f8FjqFUpawIDAQABAkAPejKaBYHrwUqUEEOe8lpnB6lBAsQIUFnQI/vXU4MV+MhIzW0BLVZCiarIQqUXeOhThVWXKFt8GxCykrrUsQ6BAiEA4vMVxEHBovz1di3aozzFvSMdsjTcYRRo82hS5Ru2/OECIQC2fAPoXixVTVY7bNMeuxCP4954ZkXp7fEPDINCjcQDywIgcc8XLkkPcs3Jxk7uYofaXaPbg39wuJpEmzPIxi3k0OECIGubmdpOnin3HuCP/bbjbJLNNoUdGiEmFL5hDI4UdwAdAiEAtcAwbm08bKN7pwwvyqaCBC//VnEWaq39DCzxr+Z2EIk=";
	
	public static void main(String[] args) throws Exception {
		String plainText, secretText;
//    	secretText = "nxj18v0o2vmjDq2fMHbqzZUHFTAI7wtnjxEx3iqFTgSrPSjKjPMaIzLM6szCB7KMjmvLkINwZEeV+HjlNuH+tw==";
		secretText = "TMTqOMf9NPU8o+9yKukVX7RCViZhRB4gtzWb6QT3Drr9ROvjcdKPNgpwPV2XpoY8gCvb5yj4LZFYvyYTbSg8lw==";
		secretText = "dNgJdJeYU0ZaCKOM9m3QWy/0HsYrihoRAmymzCHKCjzgykqwCNBCKiWw/7yYIPj9qsdWAk3qJW8j65bRwP8frA==";
		System.out.println(decrypt(secretText));
		
		plainText = "RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());";
		secretText = encryptBlock(plainText.getBytes());
		System.out.println(secretText);
		System.out.println(new String(decryptBlock(secretText)));
		System.out.println();
		
		String file = "E:/sumpay/conf/druid/cert/tomcat-1.0.jks";
		char[] password = "123456".toCharArray();
		byte[] encoded;
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(file), password);
		encoded = keyStore.getKey("tomcat", password).getEncoded();
		secretText = encryptBlock(encoded);
		System.out.println(secretText);
		System.out.println(new String(decryptBlock(secretText)));
		System.out.println();
      
		file = "E:/openxsl/conf/druid/cert/tomcat-1.0.cer";
		encoded = getPublicKeyByX509(file).getEncoded();
		System.out.println(new String(encoded));
		secretText = encryptBlock(encoded);
		System.out.println(new String(decryptBlock(secretText)));
	}
	
	public static String encryptBlock(byte[] bytes) throws Exception {
		PublicKey key = getPublicKey((String)null);  //DEFAULT_PUBLIC_KEY_STRING
		byte[] data = StaticEncryptor.encrypt(bytes, key);
		return java.util.Base64.getEncoder().encodeToString(data);
	}
	
	public static byte[] decryptBlock(String secretText) throws Exception {
		PrivateKey privateKey = getPrivateKey((String)null);
		byte[] data = java.util.Base64.getDecoder().decode(secretText);
		return StaticEncryptor.decrypt(data, privateKey);
	}
	
	public static PublicKey getPublicKey(byte[] keyData) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
			return keyFactory.generatePublic(new X509EncodedKeySpec(keyData));
		} catch (Exception e) {
			throw new IllegalArgumentException("Failed to get public key", e);
		}
	}
	public static PrivateKey getPrivateKey(byte[] keyData) {
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA", "SunRsaSign");
			return factory.generatePrivate(new PKCS8EncodedKeySpec(keyData));
		} catch (Exception e) {
			throw new IllegalArgumentException("Failed to get private key", e);
		}
	}
	
	public static PrivateKey getPrivateKey(String keys) {
		if (keys == null || keys.length() == 0) {
			keys = DEFAULT_PRIVATE_KEY_STRING;
		}
		byte[] keyBytes = Base64.base64ToByteArray(keys);
		
		return getPrivateKey(keyBytes);
	}
}
