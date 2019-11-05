package com.openxsl.config;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * 调用远程证书中心
 * @author xiongsl
 */
@Component("druidRestInvoker")
public class RestInvoker implements InitializingBean{//, ApplicationContextAware{
	@Autowired(required=false)
	private RestTemplate rest;
	private String charset = "UTF-8";
	
	@Override
	public void afterPropertiesSet() throws Exception {
		if (rest == null) {
			rest = new RestTemplate();
			rest.setErrorHandler(new ListableResponseErrorHandler());
//			filters.load("http");  //http-trace-filter
//			for (TracingFilter filter : filters.getFilters()) {
//				if (filter instanceof ClientHttpRequestInterceptor) {
//					this.addInterceptor((ClientHttpRequestInterceptor)filter);
//				}
//				if (filter instanceof ResponseErrorHandler) {
//					errorHandlers.addErrorHandler((ResponseErrorHandler)filter);
//				}
//			}
		}
	}

	/**
	 * POST表单提交文本信息（application/x-www-form-urlencoded）
	 * @param url
	 * @param queryString
	 * @return
	 */
	public String postForm(String url, String queryString){
        return this.postString(url, queryString, MediaType.APPLICATION_FORM_URLENCODED_VALUE,
        						String.class);
	}
	
	/**
	 * POST提交JSON内容（application/json;charset=UTF-8）
	 */
	public String postJson(String url, String content){
        return this.postString(url, content, MediaType.APPLICATION_JSON_UTF8_VALUE, String.class);
	}
	
	public String postXml(String url, String content){
		return this.postString(url, content, MediaType.TEXT_XML_VALUE, String.class);
	}
	
	public final <T> T postString(String url, String content, String contentType, Class<T> returnType){
    	HttpHeaders headers = new HttpHeaders();
		headers.add("Content-Type", contentType);
		headers.add("Accept-Charset", charset);
        Object request = new HttpEntity<String>(content, headers);
        return rest.postForObject(url, request, returnType);
	}
	
	public <T> T get(String url, String content, String contentType, Class<T> returnType) {
		T result = null;
        try {
        	HttpHeaders headers = new HttpHeaders();
    		headers.add("Content-Type", contentType);
    		headers.add("Accept-Charset", charset);
            Object request = new HttpEntity<String>(content, headers);
        	result = rest.getForObject(url, returnType, request);
        	return result;
        } finally{
//        	filters.after(result);
		}
	}
	
	public <T> void delete(String url, String content, String contentType, Class<T> returnType) {
//		filters.before(url, "delete", content);
        try {
        	HttpHeaders headers = new HttpHeaders();
    		headers.add("Content-Type", contentType);
    		headers.add("Accept-Charset", charset);
            Object request = new HttpEntity<String>(content, headers);
        	rest.delete(url, request);
        } finally{
//        	filters.after(null);
		}
	}
	
	/** 添加拦截器将会在请求之前执行，可用于签名 */
	public void setInterceptors(List<ClientHttpRequestInterceptor> interceptors){
		rest.setInterceptors(interceptors);
	}
	public void addInterceptor(ClientHttpRequestInterceptor interceptor){
		rest.getInterceptors().add(interceptor);
	}
	/** 添加消息转换器，会在返回结果之前执行，可用于验签*/
	@Deprecated
	public void addResultConverter(HttpMessageConverter<?> converter){
		rest.getMessageConverters().add(converter);
	}
	public void replaceResultConverter(Class<? extends HttpMessageConverter<?>> type,
						HttpMessageConverter<?> converter){
		int idx = -1, i=0;
		for (HttpMessageConverter<?> older : rest.getMessageConverters()){
			if (older.getClass() == type){
				idx = i;
				break;
			}
			i++;
		}
		if (idx != -1){
			rest.getMessageConverters().remove(idx);
			rest.getMessageConverters().add(idx, converter);
		}
	}
	/**
	 * 添加Response异常处理器
	 * @param errorHandler
	 */
	public void addResponseHandler(ResponseErrorHandler errorHandler) {
		((ListableResponseErrorHandler)rest.getErrorHandler()).addErrorHandler(errorHandler);
	}
	public void setCharset(String charset) {
		this.charset = charset;
	}
	
//	public interface TraceHandler{
//		void preHandle(String uri, String method, Object request);
//		
//		void postHandle();
//	}
//	
//	/**
//	 * 调用链
//	 * @author xiongsl
//	 */
//	class ListableTraceHandler implements TraceHandler{
//		private List<TraceHandler> handlers = new ArrayList<TraceHandler>(2);
//		
//		public void add(TraceHandler handler) {
//			handlers.add(handler);
//		}
//
//		@Override
//		public void preHandle(String uri, String method, Object request) {
//			for (TraceHandler handler : handlers) {
//				try {
//					handler.preHandle(uri, method, request);
//				} catch(Throwable t) {
//					//
//				}
//			}
//		}
//
//		@Override
//		public void postHandle() {
//			for (TraceHandler handler : handlers) {
//				try {
//					handler.postHandle();
//				} catch(Throwable t) {
//					//
//				}
//			}
//		}
//	}
	/**
	 * 处理返回结果
	 * @author xiongsl
	 */
	class ListableResponseErrorHandler implements ResponseErrorHandler{
		private List<ResponseErrorHandler> handlers = new ArrayList<ResponseErrorHandler>(2);
		
		ListableResponseErrorHandler(){
			handlers.add(new DefaultResponseErrorHandler());   //HttpStatus
		}
		
		public ListableResponseErrorHandler addErrorHandler(ResponseErrorHandler errorHandler) {
			handlers.add(errorHandler);
			return this;
		}

		@Override
		public boolean hasError(ClientHttpResponse response) throws IOException {
			return true;
		}

		@Override
		public void handleError(ClientHttpResponse response) throws IOException {
			for (ResponseErrorHandler handler : handlers) {
				if (handler.hasError(response)) {
					handler.handleError(response);
				}
			}
		}
		
	}
	
	/**
	 * Https安全协议
	 * @author xiongsl
	 */
	//org.apache.http.conn.ssl.DefaultHostnameVerifier
	public static class InnerHostnameVerifier implements HostnameVerifier{
		private String certId;
		
		@Override
		public boolean verify(String hostname, SSLSession session) {
			if (certId!=null && certId.length()>0) {
				//TODO
			}
			return true;
		}
		public void setCertId(String certId) {
			this.certId = certId;
		}
	}
	public static class InnerSSLContextBuilder {
		final TrustStrategy trustStrategy = new TrustStrategy() {
			@Override
			public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				return true;
			}
		};
		public SSLContext build() throws Exception {
			KeyStore keyStore = null;
			return new SSLContextBuilder().loadTrustMaterial(keyStore, trustStrategy)
							.build();
		}
	}
//	@Override
//	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
//		parentContext = (AbstractApplicationContext)applicationContext;
//	}

}
