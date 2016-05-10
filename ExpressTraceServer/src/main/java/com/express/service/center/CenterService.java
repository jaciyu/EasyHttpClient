package com.express.service.center;

import java.util.Map;

import javax.annotation.Resource;

import org.springframework.stereotype.Component;

import com.express.service.base.ISelectService;

/**
 * 分发器
 * @author yuwenjin
 * @date 2016年5月6日
 */
@Component
public class CenterService {
	@Resource
	private Map<String, ISelectService> partnerMap;
	public Map<String, Object> selectReult(Map<String, Object> params){
		String partner = params.get("com")==null?"":params.get("com").toString();
		ISelectService selectService = this.getService(partner);
		return selectService.selectResult(params);
	}
	private ISelectService getService(String key){
		return partnerMap.get(key);
	}
}
