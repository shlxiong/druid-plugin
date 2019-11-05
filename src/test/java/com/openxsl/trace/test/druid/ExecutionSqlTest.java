package com.openxsl.trace.test.druid;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;

import com.openxsl.config.testuse.AutoConfig;
import com.openxsl.config.testuse.BasicTest;
import com.openxsl.testweb.service.ServiceConfigDao;
import com.openxsl.testweb.service.TestService;

@ContextConfiguration(locations= {
		"classpath*:spring/dal/http-client.xml",
		"classpath*:spring/dal/druid.xml"
})
@AutoConfig(application="springboot-test")
public class ExecutionSqlTest extends BasicTest{
	@Autowired
	private ServiceConfigDao serviceDao;
	@Autowired
	private TestService testService;
	
	@Test
	public void test() {
		System.out.println(serviceDao.queryForPage(null, 0, 10).getResults());
		testService.hello();
//		System.out.println(TraceCollector.getRpcTrace());
	}
	
}
