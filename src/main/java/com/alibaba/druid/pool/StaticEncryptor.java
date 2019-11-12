package com.alibaba.druid.pool;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JCE
 * @author xiongsl
 */
public class StaticEncryptor {
	private static final int BLOCK_SIZE = 64;   //64,128,256
	private static Logger logger = LoggerFactory.getLogger(StaticEncryptor.class);
	
	/**
	 * 加密二进制数据
	 * @param data
	 * @param key
	 * @param algorithm
	 * @return
	 */
	public static final byte[] encrypt(byte[] data, Key key, String... algorithm){
		try{
			Cipher cipher = init(Cipher.ENCRYPT_MODE, key, null, algorithm);
			return process(data, cipher, BLOCK_SIZE-11);  //53,117,245
		}catch(Exception e){
			logger.error("error: ", e);
			return data;
		}
	}
	public static final byte[] decrypt(byte[] data, Key key, String... algorithm){
		try{
			Cipher cipher = init(Cipher.DECRYPT_MODE, key, null, algorithm);
			return process(data, cipher, BLOCK_SIZE);  //64,128,256
		}catch(Exception e){
			logger.error("error: ", e);
			return data;
		}
	}
	
	/**
	 * 读取加密文件流
	 * @param inputStream
	 * @param key
	 * @param algorithm
	 * @return
	 */
	public static final InputStream decrypt(InputStream inputStream, Key key,
					String... algorithm){
		try {
			Cipher cipher = init(Cipher.DECRYPT_MODE, key, null, algorithm);
            return new CipherInputStream(inputStream, cipher);
        }catch(Exception e){
        	logger.error("error: ", e);
        	return inputStream;
        }
	}
	
	protected static Cipher init(int mode, Key key, AlgorithmParameterSpec paramSpec, 
				   String...algorithm) throws EncryptException{
		String algr = (algorithm.length>0 && algorithm[0]!=null) ? algorithm[0]
					: key.getAlgorithm();
		try{
			Cipher cipher = Cipher.getInstance(algr);
			if (paramSpec == null){
				cipher.init(mode, key);
			}else{
				cipher.init(mode, key, paramSpec);
			}
			return cipher;
		}catch(Exception e){
			throw new EncryptException(e);
		}
	}
	
	private static byte[] process(byte[] data, Cipher cipher, int blockSize)
				throws EncryptException{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] cache;
		int len = data.length, offset = 0;
		try{
			while (len > offset){
				int size = Math.min(len-offset,blockSize);
				cache = cipher.doFinal(data, offset, size);
				out.write(cache);
				offset += blockSize;
			}
			cache = out.toByteArray();
			out.close();
		}catch(Exception e){
			e.printStackTrace();
			throw new EncryptException(e);
		}
		cipher = null;
		return cache;
	}
	
	@SuppressWarnings("serial")
	static class EncryptException extends SecurityException {
		
		public EncryptException(String message) {
			super(message);
		}
		
		public EncryptException(Throwable e){
			super(e);
		}
		
		public EncryptException(String message, Throwable e){
			super(message, e);
		}

	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		String plainText = "RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());"
				+ "RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());";
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(2048);   //1024-error
		KeyPair pair = pairGen.generateKeyPair();
		String secretText = Base64.getEncoder().encodeToString(
				encrypt(plainText.getBytes(), pair.getPublic()));
		System.out.println(secretText);
		byte[] data = decrypt(Base64.getDecoder().decode(secretText), pair.getPrivate());
		System.out.println(new String(data));
	}

}
