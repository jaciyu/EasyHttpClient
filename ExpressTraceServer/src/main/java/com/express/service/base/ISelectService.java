package com.express.service.base;

import java.util.Map;

public interface ISelectService {
	/**
	 * 快递单查询
	 * @param model
	 * @return
	 * @author yuwenjin
	 */
	public Map<String, Object> selectResult(Map<String, Object> model);
}
