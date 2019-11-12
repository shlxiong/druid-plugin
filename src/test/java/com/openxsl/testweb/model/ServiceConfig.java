package com.openxsl.testweb.model;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

/**
 * 业务配置
 * @author xiongsl
 */
@Table(name="notify_service_config")
@NamedQuery(name="deleteTemplate",
		query="UPDATE ServiceConfig SET template = null WHERE template = :template")
public class ServiceConfig {
	@Id
	@Column(name="service_id", length=32)
	private String serviceId;   //业务ID
	@Column(length=127)
	private String descript;    //描述
	@Column(length=8)
	private String protocol;    //协议：@see MsgTypeEnum
	@Column(length=127)
	private String registry;    //发送通知的公众账号
	@Column(name="target_url", length=127)
	private String targetUrl;   //目标地址（Http或Dubbo服务名）
	@Column(name="host_id", length=48)
	private String hostId;      //请求的机器标识（固定IP、Mac等）
	@Column(length=31)
	private String method;      //方法名（POST/GET）
	@Column(length=1023)
	private String template;    //参数模板（或模板编号）
	@Column(length=1023)
	private String results;     //结果模板，先保留
	@Column(name="callback_url", length=127)
	private String callbackUrl; //业务平台的通知地址
	@Column
	private boolean async;      //是否异步服务
	@Column
	private boolean disabled;   //禁用标识
	
	@Column(name="biz_sys", length=32)
	private String bizSys;      //所属业务平台
	@Column(length=64)
	private String password;    //接入密码
	@Column(length=15)
	private String pswdtype;    //密码类型 @see SecurCheckEnum
	@Column(name="limit_cnt", length=127)
	private String limitCnt;    //条数限制（json）
	@Column(name="last_modified")
	private Date lastModified;
	
	public String getServiceId() {
		return serviceId;
	}
	public void setServiceId(String serviceId) {
		this.serviceId = serviceId;
	}
	public String getDescript() {
		return descript;
	}
	public void setDescript(String descript) {
		this.descript = descript;
	}
	public String getProtocol() {
		return protocol;
	}
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
	public String getTemplate() {
		return template;
	}
	public void setTemplate(String template) {
		this.template = template;
	}
	public String getResults() {
		return results;
	}
	public void setResults(String results) {
		this.results = results;
	}
	public boolean isDisabled() {
		return disabled;
	}
	public void setDisabled(boolean disabled) {
		this.disabled = disabled;
	}
	public String getBizSys() {
		return bizSys;
	}
	public void setBizSys(String bizSys) {
		this.bizSys = bizSys;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getRegistry() {
		return registry;
	}
	public void setRegistry(String registry) {
		this.registry = registry;
	}
	public String getCallbackUrl() {
		return callbackUrl;
	}
	public void setCallbackUrl(String callbackUrl) {
		this.callbackUrl = callbackUrl;
	}
	public String getPswdtype() {
		return pswdtype;
	}
	public void setPswdtype(String pswdtype) {
		this.pswdtype = pswdtype;
	}
	public String getLimitCnt() {
		return limitCnt;
	}
	public void setLimitCnt(String limitCnt) {
		this.limitCnt = limitCnt;
	}
	public Date getLastModified() {
		return lastModified;
	}
	public void setLastModified(Date lastModified) {
		this.lastModified = lastModified;
	}
	public String getTargetUrl() {
		return targetUrl;
	}
	public void setTargetUrl(String targetUrl) {
		this.targetUrl = targetUrl;
	}
	public String getMethod() {
		return method;
	}
	public void setMethod(String method) {
		this.method = method;
	}
	public boolean isAsync() {
		return async;
	}
	public void setAsync(boolean async) {
		this.async = async;
	}
	public String getHostId() {
		return hostId;
	}
	public void setHostId(String hostId) {
		this.hostId = hostId;
	}

}
