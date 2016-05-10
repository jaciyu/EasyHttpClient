package com.express.service.base.impl;

import java.util.HashMap;
import java.util.Map;

import com.express.service.base.ISelectService;

/**
 *
 * @author yuwenjin
 * @date 2016年5月6日
 */
public abstract class SelectService implements ISelectService{
	@Override
	public Map<String, Object> selectResult(Map<String, Object> model){
		Map<String, Object> result = new HashMap<String, Object>();
		result.put("msg", "请实现对应的查询");
		return result;
	}
}
