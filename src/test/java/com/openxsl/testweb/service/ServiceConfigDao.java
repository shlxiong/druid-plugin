package com.openxsl.testweb.service;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Update;

import com.openxsl.config.dal.jdbc.QueryMap;
import com.openxsl.config.rpcmodel.Page;
import com.openxsl.testweb.model.ServiceConfig;

/**
 * 服务配置（bizSys、template等）
 * @author xiongsl
 */
public interface ServiceConfigDao {
	
	public ServiceConfig find(String serviceId);
	
	public Page<ServiceConfig> queryForPage(QueryMap<?> wheres, int pageNo, int pageSize);
	
	@Insert("INSERT INTO notify_service_config(service_id, descript, protocol, registry,"
			+ "template, results, callback_url, disabled, biz_sys,"
			+ "password,pswdtype,limit_cnt)"
			+ "VALUES(#{serviceId}, #{descript}, #{protocol}, #{registry},"
			+ "#{template}, #{results}, #{callbackUrl}, #{disabled}, #{bizSys},"
			+ "#{password}, #{pswdtype}, #{limitCnt})")
	public String insert(ServiceConfig config);
	
	@Update("UPDATE notify_service_config SET descript=#{descript}, protocol=#{protocol},"
			+ "registry=#{registry}, template=#{template}, results=#{results},"
			+ "callback_url=#{callbackUrl}, disabled=#{disabled}, biz_sys=#{bizSys},"
			+ "password=#{password}, pswdtype=#{pswdtype}, limit_cnt=#{limitCnt}"
			+ " WHERE service_id=#{serviceId}")
	public int update(ServiceConfig config);
	
	@Update("UPDATE notify_service_config SET disabled=#{arg1}"
			+ " WHERE service_id=#{arg0}")
	public void disableService(String serviceId, boolean disabled);
	
	public int updateTemplate(String template, String service);
	
	public void disableTemplate(String templCode);
	
}
