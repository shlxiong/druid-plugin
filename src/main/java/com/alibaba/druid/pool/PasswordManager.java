package com.alibaba.druid.pool;

import java.awt.IllegalComponentStateException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.util.ClassUtils;

import com.alibaba.druid.filter.config.ConfigFilter;
import com.alibaba.druid.filter.config.ConfigTools;
import com.alibaba.druid.util.Base64;
import com.alibaba.druid.util.DruidPasswordCallback;

/**
 * <B>Druid加密处理</B>
 * 由于DruidDataSource中保存的是密码明文，很容易被开发者盗取；
 * 用法：DruidAbstractDataSource.createPhysicalConnection(String,Properties)
 *     -> passwodMgr.decryptIfNecessary(info, this);
 * 
 * @author xiongsl
 */
public class PasswordManager {
	public static final String ENCRYPT_CERT = "config.decrypt.cert";
	private static final Pattern PATTERN_PACKAGE = Pattern.compile(
				"^com.alibaba.druid.(filter|wall).(.*)");
	private static final Pattern PATTERN_JAR = Pattern.compile(
				"(.*)/druid-(.*).jar(!/)?$");  //spring-boot jar会增加两个字符
	private static final ClassLoader CLR = ClassUtils.getDefaultClassLoader();
	private static final Logger logger = LoggerFactory.getLogger("druid.PasswordManager");
	
	/**证书中心*/
	@Autowired(required=false)
	private CC center;
	private ApplicationContext context;
	private boolean filterChecked;
	/**不能对外暴露！！*/
	private final MyPasswordCallback passwordCallback = new MyPasswordCallback();

	public CC getCC() {
		if (center == null) {
			center = this.getDefaultCC();
		}
		return center;
	}
	public CC getDefaultCC() {
		return new CC_LOCAL();
	}
	
	/**
	 * 使用SumpayPasswodCallback 对password属性解密
	 * @see DruidAbstractDataSource#createPhysicalConnection(String, Properties)
	 * @param properties  包含user和password
	 */
	public void decryptIfNecessary(Properties properties, DruidAbstractDataSource dataSource) {
		if (!filterChecked) {
			for (String filterClass : dataSource.getFilterClassNames()) {
				this.ensureOrginalFilter(filterClass);
			}
			filterChecked = true;
			passwordCallback.setCC(this.getCC());
		}
		if (this.encrypted(dataSource)) {
			this.getCC().setToken(properties.getProperty("token"));
			passwordCallback.setProperties(dataSource.getConnectProperties());
//			passwordCallback.setUrl(dataSource.getUrl());
			passwordCallback.setPassword(dataSource.getPassword().toCharArray());
			properties.setProperty(DruidDataSourceFactory.PROP_PASSWORD,
							passwordCallback.getPasswords());
		}
	}
	
	/**
	 * 排除用户自定义的Filter
	 * @param filterClass
	 */
	private void ensureOrginalFilter(String filterClass) {
		if (Boolean.parseBoolean(System.getProperty("druid.debug","false"))) {
			return;
		}
		boolean flag = PATTERN_PACKAGE.matcher(filterClass).matches();
		if (flag){
			try {
				URL url = CLR.loadClass(filterClass).getProtectionDomain()
								.getCodeSource().getLocation();
				flag = PATTERN_JAR.matcher(url.toString()).matches();
				logger.info("find filter:{}, it's url: {}", filterClass, url);
			} catch(ClassNotFoundException cnf) {
				logger.error("", cnf);
			}
		}
		if (!flag) {
			throw new IllegalComponentStateException(
						"出于安全考虑，禁止使用非官方的Druid-Filter：" + filterClass);
		}
	}
	/**
	 * 是否需要解密（线上环境必须解密）
	 */
	private boolean encrypted(DruidAbstractDataSource dataSource) {
		for (String environ : this.getEnviron()) {
			if ("prod".equals(environ)) {  //默认是线上环境，否则必须设置“spring.profiles.active”
				return true;
			}
		}
		
		String decrypterId = dataSource.getConnectProperties()
					.getProperty(ConfigFilter.CONFIG_DECRYPT);
        if (decrypterId == null || decrypterId.length() == 0) {
            decrypterId = System.getProperty(ConfigFilter.SYS_PROP_CONFIG_DECRYPT);
        }
        boolean flag =  Boolean.valueOf(decrypterId);
        if (!flag) {
        	String cert = dataSource.getConnectProperties().getProperty(ENCRYPT_CERT);
        	flag = (cert!=null && !"".equals(cert));
        }
        return flag;
	}
	
	private final String[] getEnviron() {
		String[] profiles = {};
		if (context != null) {
			profiles = context.getEnvironment().getActiveProfiles();
		} else {
			String temp = System.getProperty("spring.profiles.active");
			if (temp != null) {
				profiles = temp.split(",");
			}
		}
		if (profiles == null || profiles.length < 1) {
			profiles = new String[]{"prod"};
		}
		return profiles;
	}
	
	/**
	 * 公钥加密，私钥解密
	 * @author xiongsl
	 */
	@SuppressWarnings("serial")
	class MyPasswordCallback extends DruidPasswordCallback{
		private final String ALGORITHM = "RSA/ECB/PKCS1Padding";
		private final boolean debug;
		private CertificateManager certMgr;
		private Cipher machine = null;
		private byte[] secret;
		
		MyPasswordCallback() {
			debug = Boolean.parseBoolean(System.getProperty("druid.debug","false"));
			try {
				machine = Cipher.getInstance(ALGORITHM);
			} catch (Throwable e) {
				logger.error("SumpayPasswordCallback has no algorithm:{}", ALGORITHM);
			}
		}
		void setCC(CC certCenter) {
			try {
				certMgr = new CertificateManager(certCenter);
				certMgr.initKeyStore();
			} catch (IOException ioe) {
				throw new IllegalStateException(ioe);
			}
		}
		
		/**
		 * DruidPasswordCallback#properties中包含"user", "password", "connectProperties"。
		 * 如果是远程服务，可以根据user获取password，这里做证书解密
		 */
		String getPasswords(){
			String password = new String(super.getPassword());
			String certId = this.getProperties().getProperty(PasswordManager.ENCRYPT_CERT);
			return this.decrypt(password, certId);
		}
		
		final String decrypt(String secretText, String certId){
			String plainText = secretText;
			if (machine == null) {
				logger.error("SumpayPasswordCallback NOT supports algorithm: {}", ALGORITHM);
				//return plainText directly
			} else if (secret == null) {  //RSA-2048:6-7ms
				synchronized (machine) {
					try {
						machine.init(Cipher.DECRYPT_MODE, certMgr.getPrivateKey(certId));
//						logger.error("password={}", secretText);
//						byte[] keys = certMgr.getPrivateKey(certId).getEncoded();
//						logger.error("cert={}, key={}", certId, Base64.byteArrayToBase64(keys));
						byte[] encoded = Base64.base64ToByteArray(secretText);
						secret = machine.doFinal(encoded);
						plainText = new String(secret, "UTF-8");
						secret = exchange(secret);
					} catch (Exception e) {
						logger.error("SumpayPasswordCallback decrypt error: ", e);
					}
				}
			} else {
				try {
					byte[] data = exchange(secret);
					plainText = new String(data, "UTF-8");
				} catch (Exception e) {
					logger.error("SumpayPasswordCallback decrypt error: ", e);
				}
			}
			
			return plainText;
		}
		
		final String encrypt(String plainPwsd, String alias){
			if (machine == null) {
				return plainPwsd;
			}
			String cipherText = plainPwsd;
			synchronized (machine) {
		        try {
		        	machine.init(Cipher.ENCRYPT_MODE, certMgr.getPublicKey(alias));
				    byte[] encryptedBytes = machine.doFinal(plainPwsd.getBytes("UTF-8"));
				    cipherText = Base64.byteArrayToBase64(encryptedBytes);
		        } catch (Exception e) {
		        	logger.error("SumpayPasswordCallback encrypt error: ", e);
		        }
			}
	        return cipherText;
		}
		
		final byte[] exchange(byte[] source) {
			if (!debug) {
				StackTraceElement[] stackTraces = Thread.currentThread().getStackTrace();
				String callerClass = stackTraces[6].getClassName();
				String methodName = stackTraces[6].getMethodName();
				if (!"createPhysicalConnection".equals(methodName) ||
				    !callerClass.equals(DruidAbstractDataSource.class.getName())) {
					return "Error".getBytes();
				}
			}
			final int len = source.length;
			final byte[] data = new byte[len];
			System.arraycopy(source, 0, data, 0, len);
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
	
	/**
	 * 证书管理器
	 * @author xiongsl
	 */
	class CertificateManager {
	    private Map<String, PublicKey> publicKeyMap = new HashMap<String, PublicKey>();
	    private Map<String, PrivateKey> privateKeyMap = new HashMap<String, PrivateKey>();
	    
	    private CC center;
	    public CertificateManager(CC cc) {
	    	this.center = cc;
	    }
	    
	    public void initKeyStore() throws IOException {
	    	publicKeyMap.clear();
	    	privateKeyMap.clear();
	    	String environ = Arrays.toString(PasswordManager.this.getEnviron());  //[DEV]
	    	environ = environ.substring(1, environ.length()-1);
	    	try {
	    		this.center.listSecureKeys(environ, publicKeyMap, privateKeyMap);
	    	} catch (Exception e) {}
	    }
	    
	    public void newKeyStore(String alias, String storePass, String version) throws Exception {
	    	String environ = Arrays.toString(PasswordManager.this.getEnviron());
	    	environ = environ.substring(1, environ.length()-1);
	    	String certId = String.format("%s-%s", alias,version);
	    	this.center.generCert(environ, certId, storePass);
	    }
	    
	    public PublicKey getPublicKey(String certId) throws IOException {
	    	if (!publicKeyMap.containsKey(certId)) {
	    		String environ = Arrays.toString(PasswordManager.this.getEnviron());
	    		environ = environ.substring(1, environ.length()-1);
	    		publicKeyMap.put(certId, center.getPublicKey(environ, certId));
	    	}
	    	return publicKeyMap.get(certId);
	    }
	    public PrivateKey getPrivateKey(String certId) throws IOException {
	    	if (!privateKeyMap.containsKey(certId)) {
	    		String environ = Arrays.toString(PasswordManager.this.getEnviron());
	    		environ = environ.substring(1, environ.length()-1);
	    		privateKeyMap.put(certId, center.getPrivateKey(environ, certId));
	    	}
	    	return privateKeyMap.get(certId);
	    }
	    
	}
	
	public interface CC{
		public static final String KEY_CERT_PATH = "certs.directory";
		public static final String DIR = "/openxsl/conf/druid/";
		
		/**
		 * 生成一个证书，保存到环境中(environ)
		 * @return 证书路径
		 */
		String generCert(String environ, String certId, String storePass) throws IOException;
		
		/**
		 * 加载环境中(environ)的所有的公私钥证书
		 */
		void listSecureKeys(String environ, Map<String,PublicKey> publicKeyMap,
							Map<String,PrivateKey> privateKeyMap) throws IOException;
		
		PublicKey getPublicKey(String environ, String certId) throws IOException;
		
		PrivateKey getPrivateKey(String environ, String certId) throws IOException;
		
		void setToken(String token);
		
	}
	
	static class KeyStoreUtils{
		
		public static void generCommands(String alias, String storePass, String version)
					throws IOException {
			String certId = String.format("%s-%s", alias,version);
			String storeCmd = "keytool -genkey -alias %s -keypass %s -keyalg RSA -keysize 2048"
					+ " -keystore %s.jks -storepass %s -storetype PKCS12 -validity 730 -dname \"C=COM,CN=openxsl.cn\"";
			String certCmd = "keytool -export -alias %s -keystore %s.jks -file %s.cer -storepass %s";
			String os = System.getProperty("os.name", "windows");
			if (os.toLowerCase().startsWith("windows")) {
				storePass = '"'+storePass+'"';
			} else {
				storePass = '\''+storePass+'\'';
			}
			
//			System.out.println("请在控制台分别执行以下（证书）命令：");
//			System.out.printf(storeCmd, alias,storePass,alias,storePass);
//			System.out.printf(certCmd, alias,alias,alias,storePass);
			executeCommand(String.format(storeCmd, alias,storePass,certId,storePass));
			executeCommand(String.format(certCmd, alias,certId,certId,storePass));
		}
		
	    public static PrivateKey getPrivateKey(File storeFile, String password) throws Exception{
			KeyStore keyStore = getKeyStore(storeFile, password);
			if (keyStore != null){
				char[] chars = password.toCharArray();
				Enumeration<String> enumeration = keyStore.aliases();
				while (enumeration.hasMoreElements()) {
					String alias = enumeration.nextElement();
					return (PrivateKey)keyStore.getKey(alias, chars);
				}
			}

			return null;
		}
		public static PublicKey getPublicKey(String certFile) throws Exception{
			return getCertificate(certFile).getPublicKey();
		}
		
		/**
		 * 对密钥做简单加减密，可以自定义扩展
		 */
		public static String encrypt(String plainText) throws Exception {
			return ConfigTools.encrypt(plainText);
		}
		public static String decrypt(String secreText) throws Exception {
			return ConfigTools.decrypt(secreText);
		}
		
		private static void executeCommand(String command) throws IOException {
			System.out.println("执行脚本：" + command);
			String os = System.getProperty("os.name");
			Process proc;
			if (os.toLowerCase().startsWith("windows")) {
				proc = Runtime.getRuntime().exec("cmd /c "+command);
			}else {
				String[] commands = new String[]{"/bin/sh", "-c", command};
				proc = Runtime.getRuntime().exec(commands);
			}
			int value = 0;
			try {
				value = proc.waitFor();
			} catch (InterruptedException e) {
			}
			InputStream is = (value==0) ? proc.getInputStream() : proc.getErrorStream();
			String charset = System.getProperty("sun.jnu.encoding", "GBK");
			BufferedReader reader = new BufferedReader(new InputStreamReader(is, charset));
			StringBuilder sb = new StringBuilder();
			sb.append(value).append("\n\t");
			String line;
	        while ((line = reader.readLine()) != null) {
	            sb.append(line).append("\n");
	        }
	        System.out.println("运行结果："+sb.toString());
	        reader.close();
		}
		private static File removeFile(File source, String destPath)throws IOException{
			File destFile = new File(destPath, source.getName());
			if (destFile.exists()) {
				destFile.delete();
			}
			boolean succ = source.renameTo(destFile);
			if (!succ) { //Linux无权限
				executeCommand("sudo mv "+source+" "+destPath);
			}
			source.delete();
			return destFile;
		}
		private static KeyStore getKeyStore(File storeFile, String password) throws Exception {
	        KeyStore keyStore = null;
			if (storeFile.getName().endsWith(".pfx")){
				keyStore = KeyStore.getInstance("PKCS12");
			}else{// if (storeFile.endsWith(".jks")){
				keyStore = KeyStore.getInstance("JKS");
			}
			if (keyStore != null){
				FileInputStream fis = new FileInputStream(storeFile);
				try {
					keyStore.load(fis, password.toCharArray());
				}finally{
					fis.close();
				}
			}
	        return keyStore;
	    }
		private static Certificate getCertificate(String certFile) throws IOException,CertificateException{
			FileInputStream fis = new FileInputStream(certFile);
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			try{
				return factory.generateCertificate(fis);
			}finally{
				fis.close();
			}
		}
    }
	
	public static void main(String[] args) throws Exception {
		if (args.length<1 || "-help".equals(args[0])) {
			StringBuilder help = new StringBuilder();
			help.append("用法: java -jar druid-plugin-1.1.5.beta-jar-with-dependencies.jar [args...]\n");
			help.append("其中选项包括:\n");
			help.append("-alias       证书名称\n")
				.append("-storePass   证书密码\n")
				.append("-version     证书版本\n")
				.append("-dbPass      数据库密码\n")
				.append("-genCert     是否重新生成证书");
			System.out.println(help.toString());
			return;
		}
//		System.out.println(ConfigTools.encrypt("root"));
//		System.exit(-1);
		
		PasswordManager manager = new PasswordManager();
		MyPasswordCallback callback = manager.passwordCallback;
		callback.setCC(manager.getCC());
		/*/性能测试
		String plainPswd = "yu23m32_kjde";
		String secretText = callback.encrypt(plainPswd, "tomcat-1.0");
		long start = System.currentTimeMillis();
		final int loop = 10000;
		for (int i=0; i<loop; i++) {
			callback.decrypt(secretText, "tomcat-1.0");
		}
		System.out.printf("run %d spends %d ms", loop,(System.currentTimeMillis()-start));
		*/
		
		String alias = args.length>0 ? args[0] : "tomcat";
		String keyPass = args.length>1 ? args[1] : "123456";
		String version = args.length>2 ? args[2] : "1.0";
		String dbPass = args.length>3 ? args[3] : "";
		String genCers = args.length>4 ? args[4] : "true";
		Properties props = new Properties();
		File file = new File(CC.DIR, "openxsl-db.properties");
		if (file.exists()) {
			FileInputStream fis = new FileInputStream(file);
			props.load(fis);
			dbPass = ConfigTools.decrypt(props.getProperty("password"));
			fis.close();
		} else if (dbPass.length() == 0) {
			System.out.println("请输入数据库密码：");
			byte[] data = new byte[64];
			System.in.read(data);
			dbPass = new String(data);
		}
		
		String certId = alias+"-"+version;
		if (Boolean.valueOf(genCers)) {
			if (callback.certMgr.publicKeyMap.containsKey(certId)) {
				System.out.println("该证书已经存在，请确认是否要重新生成？（是-Y，否-N）");
				byte[] data = new byte[4];
				System.in.read(data);
				if (data[0] == 'N') {
					System.exit(-1);
				}
			}
			callback.certMgr.newKeyStore(alias, keyPass, version);
		}
		
		System.out.println("\n*****Successful******");
		String encoded = callback.encrypt(dbPass, certId);
		if (file.exists()) {
			props.setProperty("password", encoded);
			String targetFile = CC.DIR + file.getName();
			props.store(new FileOutputStream(targetFile), "");
			System.out.println("请拷贝"+targetFile+"到源路径.....\n");
		} else {
			System.out.println("请牢记下面数据库密码:\n"+encoded);
		}
		
		if (Boolean.parseBoolean(System.getProperty("druid.debug","false"))) {
			callback.setPassword(encoded.toCharArray());
			//模拟场景PasswordManager#decryptIfNecessary
			Properties connectProps = new Properties();
			connectProps.setProperty(PasswordManager.ENCRYPT_CERT, certId);
			callback.setProperties(connectProps);
			callback.setUrl("something jdbcUrl");
			
			String sourced = callback.getPasswords();
			System.out.println("解密明文："+sourced);
		}
	}
	
	/**
	 * 本地文件系统证书库。
	 * 密码保存在 "/openxsl/conf/druid/"
	 * 证书路径由 "certs.directory"指定，默认 "/openxsl/conf/druid/cert"
	 * @author xiongsl
	 */
	static class CC_LOCAL implements CC {
		private static Properties pswdMap = new Properties();
		private final String keystoreDir;
		private final File storeFile = new File(DIR+"keystore.properties");
		
		CC_LOCAL(){
			keystoreDir = System.getProperty(KEY_CERT_PATH, DIR+"cert");
			if (!new File(keystoreDir).exists()) {
	    		new File(keystoreDir).mkdir();
	    	}
    		try {
    			if (!storeFile.exists()) {
    				storeFile.getParentFile().mkdir();
    			}
    			pswdMap.load(new FileInputStream(storeFile));
    		} catch (IOException e) {
    			logger.error("failed to read keystore.properties, because it does not exist");
			}
		}
		
		@Override
		public String generCert(String environ, String certId, String storePass) throws IOException {
			String alias = certId.split("-")[0];
			String version = certId.substring(alias.length()+1);
			KeyStoreUtils.generCommands(alias, storePass, version);     //证书在当前目录下
			File certFile = new File(certId+".cer");
			certFile = KeyStoreUtils.removeFile(certFile, keystoreDir); //移动公钥证书
			certFile = new File(certId+".jks");
			certFile = KeyStoreUtils.removeFile(certFile, keystoreDir); //移动私钥证书

			this.put(certId, storePass);
			return keystoreDir;
		}

		@Override
		public void listSecureKeys(String environ, Map<String, PublicKey> publicKeyMap, 
								Map<String, PrivateKey> privateKeyMap)	throws IOException {
	    	logger.info("loading certifications from: {}", keystoreDir);
	    	for (File file : new File(keystoreDir).listFiles()) {
	    		if (file.isDirectory()) {
	    			continue;
	    		}
	    		try{
		    		final String fullName = file.getCanonicalPath();
		    		String certId = file.getName();
		    		certId = certId.substring(0, certId.lastIndexOf("."));
		    		if (fullName.endsWith(".cer") || fullName.endsWith("crt")){
		    			publicKeyMap.put(certId, KeyStoreUtils.getPublicKey(fullName));
		    		} else {
		    			String storePass = this.get(certId);
		    			privateKeyMap.put(certId, KeyStoreUtils.getPrivateKey(file,storePass));
		    		}
	    		}catch(Exception ex){
	    			logger.error("证书加载失败：", ex);
	    		}
	    	}
	    	logger.info("loaded publicKeys: {}, privateKeys: {}", 
	    				publicKeyMap.keySet(), privateKeyMap.keySet());
		}
		
		@Override
		public PublicKey getPublicKey(String environ, String certId) throws IOException {
			File certFile = new File(keystoreDir, certId+".cer");
			if (!certFile.exists()) {
				certFile = new File(keystoreDir, certId+".crt");
			}
			try {
				return KeyStoreUtils.getPublicKey(certFile.getCanonicalPath());
			} catch (Exception e) {
				throw new IOException(e);
			}
		}

		@Override
		public PrivateKey getPrivateKey(String environ, String certId) throws IOException {
			String storePass = this.get(certId);
			File certFile = new File(keystoreDir, certId+".jks");
			if (!certFile.exists()) {
				certFile = new File(keystoreDir, certId+".pfx");
			}
			try {
				return KeyStoreUtils.getPrivateKey(certFile, storePass);
			} catch (Exception e) {
				throw new IOException(e);
			}
		}
		@Override
		public void setToken(String token) {}
		
		private void put(String certId, String storePass) throws IOException{
			try {
				storePass = KeyStoreUtils.encrypt(storePass);
			} catch (Exception e) {
				logger.error("CC_LOCAL encrypt error:", e);
			}
			pswdMap.put(certId, storePass);
			pswdMap.store(new FileOutputStream(storeFile), "####");
		}
		private String get(String certId) {
			String password = pswdMap.getProperty(certId);
			if (password == null) {
	    		throw new IllegalStateException("no authoried cert:" + certId);
	    	}
	    	try {
	    		return KeyStoreUtils.decrypt(password);
	    	}catch(Exception e) {
	    		logger.warn("CertificateManager decrypt storePass error: ", e);
	    		return password;
	    	}
		}

	}
	
}
