package com.openxsl.testweb.service;

import org.springframework.stereotype.Repository;

import com.openxsl.config.dal.jdbc.BasicDaoFacade;
import com.openxsl.config.dal.jdbc.QueryMap;
import com.openxsl.config.rpcmodel.Page;
import com.openxsl.config.util.KvPair;
import com.openxsl.testweb.model.ServiceConfig;

/**
 * ServiceConfigDao ImplmentClass
 * @author xiongsl
 */
@Repository
public class ServiceConfigDaoImpl extends BasicDaoFacade<String, ServiceConfig>
			implements ServiceConfigDao {
	
	@Override
	public Page<ServiceConfig> queryForPage(QueryMap<?> wheres, int pageNo, int pageSize){
		return pagedTemplate.queryForPage(wheres, "lastModified desc", pageNo, pageSize);
	}

	@Override
	public void disableService(String serviceId, boolean disabled) {
		QueryMap<Boolean> values = new QueryMap<>("disabled", disabled);
		pagedTemplate.update(values, serviceId);
	}

	@Override
	public int update(ServiceConfig config) {
		return pagedTemplate.updateById(config, config.getServiceId());
	}

	@Override
	public int updateTemplate(String template, String serviceId) {
		return this.update(serviceId, new KvPair("template", template));
	}
	
	public void disableTemplate(String templCode) {
		this.getTemplate().executeByNamed("deleteTemplate", templCode);
	}

}
