package com.http.easyhttpclient.lib;
/**
 * 回调处理接口
 * 
 * @author jaciyu
 * @date  2016年5月4日 
 * @version 1.0
 */
public interface IHandler {
	/**
	 * 处理异常时，执行该方法
	 * @return
	 */
	Object failed(Exception e);
	
	/**
	 * 处理正常时，执行该方法
	 * @return
	 */
	Object completed(String respBody);
	
	/**
	 * 处理取消时，执行该方法
	 * @return
	 */
	Object cancelled();
}
