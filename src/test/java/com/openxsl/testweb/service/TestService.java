package com.openxsl.testweb.service;

import com.openxsl.config.autodetect.ScanConfig;
import com.openxsl.config.filter.domain.Invoker;
import com.openxsl.config.filter.tracing.TracingCollector;

@ScanConfig
public class TestService {
	
	public void hello() {
		TracingCollector.setT1(new Invoker("unknown", getClass().getName(), "hello"));
		try {
			Thread.sleep(500);
		} catch (InterruptedException e) {
		}
		TracingCollector.setT2();
	}

}
