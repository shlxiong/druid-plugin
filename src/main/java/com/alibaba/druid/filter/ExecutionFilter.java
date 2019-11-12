package com.alibaba.druid.filter;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.proxy.jdbc.DataSourceProxy;
import com.alibaba.druid.proxy.jdbc.ResultSetProxy;
import com.alibaba.druid.proxy.jdbc.StatementProxy;
import com.openxsl.config.filter.tracing.TracingCollector;

/**
 * tracing druid-filter
 * @author xiongsl
 */
@AutoLoad
public class ExecutionFilter extends FilterEventAdapter {
	private final Pattern SQL_CAPITAL_PATTERN = Pattern.compile("^(\\w+)\\s+(.*)");
//	DataSource初始化也会执行
//	public void connection_connectBefore(FilterChain chain, Properties info) {  
//		String serviceKey = chain.getDataSource().getUrl();
//		System.out.println(Thread.currentThread().getName()+"ExecutionFilter=======getConnection");
//		TracingCollector.setT1(serviceKey);
//  }
	
	protected void statementExecuteUpdateBefore(StatementProxy statement, String sql) {
		this.saveTrace3(statement, sql);
	}

    protected void statementExecuteUpdateAfter(StatementProxy statement, String sql, int updateCount) {
    	this.finishTrace(statement);
    }

    protected void statementExecuteQueryBefore(StatementProxy statement, String sql) {
    	this.saveTrace3(statement, sql);
    }

    protected void statementExecuteQueryAfter(StatementProxy statement, String sql, ResultSetProxy resultSet) {
    	this.finishTrace(statement);
    }
//    protected void resultSetOpenAfter(ResultSetProxy resultSet) {
//    	TracingCollector.setT2();
//    }

    protected void statementExecuteBefore(StatementProxy statement, String sql) {
		this.saveTrace3(statement, sql);
    }

    protected void statementExecuteAfter(StatementProxy statement, String sql, boolean result) {
    	this.finishTrace(statement);
    }

    protected void statementExecuteBatchBefore(StatementProxy statement) {
		this.saveTrace3(statement, null);
    }

    protected void statementExecuteBatchAfter(StatementProxy statement, int[] result) {
    	this.finishTrace(statement);
    }

    protected void statement_executeErrorAfter(StatementProxy statement, String sql, Throwable error) {
    	TracingCollector.markError(error);
    	this.finishTrace(statement);
    }
    
    private final void saveTrace3(StatementProxy statement, String sql) {
    	if (ConnectionFilter.shouldTracing()) {
    		DataSourceProxy dataSource = statement.getConnectionProxy().getDirectDataSource();
        	ConnectionFilter.startTrace((DruidDataSource)dataSource);
	    	if (sql != null) {
	    		Matcher matcher = SQL_CAPITAL_PATTERN.matcher(sql);
	    		if (matcher.find()) {
	    			String method = matcher.group(1);
	    			TracingCollector.setMethodParams(sql, method);
	    		}
	    	}
	    	dataSource = null;
//    		TracingCollector.setT3();
    	}
    }
    private final void finishTrace(StatementProxy statement) {
    	if (ConnectionFilter.shouldTracing()) {
//	    	TracingCollector.setT4();
			TracingCollector.setT2();
		}
    }
    
}
