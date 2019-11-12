package com.alibaba.druid.filter;

import java.sql.SQLException;
import java.util.Properties;

import com.alibaba.druid.pool.DruidAbstractDataSource;
import com.alibaba.druid.pool.PasswordManager;
import com.alibaba.druid.proxy.jdbc.ConnectionProxy;
import com.alibaba.druid.proxy.jdbc.DataSourceProxy;

//@AutoLoad  replace by DruidConfiguration
public class PasswordFilter extends FilterAdapter {
	private DruidAbstractDataSource dataSource;
	//CC_LOCAL
	private PasswordManager passwodMgr = new PasswordManager();
	
	@Override
    public void init(DataSourceProxy dataSource) {
		this.dataSource = (DruidAbstractDataSource)dataSource;
    }
	
	@Override
    public ConnectionProxy connection_connect(FilterChain chain, Properties info) throws SQLException {
		passwodMgr.decryptIfNecessary(info, dataSource);
        return chain.connection_connect(info);
    }
	
    public void setPasswordMgr(PasswordManager manager) {
    	this.passwodMgr = manager;
    }

}
