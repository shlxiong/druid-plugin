package com.alibaba.druid.filter;

import java.sql.SQLException;

import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.pool.DruidPooledConnection;
import com.openxsl.config.Environment;
import com.openxsl.config.filter.domain.Invoker;
import com.openxsl.config.filter.tracing.TracingCollector;
import com.openxsl.config.tracing.service.protocol.JdbcRegistry;
import com.openxsl.tracing.registry.model.JdbcRegInfo;

/**
 * tracing druid-filter
 * @author xiongsl
 */
//@AutoLoad
public class ConnectionFilter extends FilterAdapter {
	private static final String PROTOCOL = JdbcRegistry.NAMESPACE;
	private static final Boolean enable;
	
	static {
		enable = Environment.getProperty("spring.tracing.enable.jdbc", Boolean.class, true);
	}
	
	public static void startTrace(DruidDataSource dataSource) {
		if (enable) {
			String jdbcUrl = dataSource.getUrl();
			String username = dataSource.getUsername();
			String serviceKey = new JdbcRegInfo(jdbcUrl, username).getServiceKey().serialize();
			Invoker invoker = new Invoker(PROTOCOL, serviceKey,"");
			invoker.setApplication(Environment.getApplication());
			TracingCollector.setT1(invoker);
		}
	}
	
	@Deprecated  //可能一个Connection执行多条sql
	@Override
    public DruidPooledConnection dataSource_getConnection(FilterChain chain, DruidDataSource dataSource,
                                       long maxWaitMillis) throws SQLException {
		startTrace(dataSource);
		return chain.dataSource_connect(dataSource, maxWaitMillis);
    }
	
//	  public void dataSource_releaseConnection(FilterChain chain, DruidPooledConnection connection) throws SQLException {
//        chain.dataSource_recycle(connection);
//    }
	
	public static final boolean shouldTracing() {
		return enable && (threadLocal.get()==null || !threadLocal.get().booleanValue());
	}
	
	private static final ThreadLocal<Boolean> threadLocal = new ThreadLocal<Boolean>();
	/**
	 * 临时开启/关闭 调用链
	 * @param flag
	 */
	public static void disableTracing(boolean flag) {
		if (flag) {
			threadLocal.set(true);
		} else {
			threadLocal.remove();
		}
	}
	
}
