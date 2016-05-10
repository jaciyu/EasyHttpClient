package com.express.core.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class DateUtil {
	/**
	 * 
	 * @param time
	 * @param format "yyyy-MM-dd HH:mm:ss"
	 * @return
	 */
	public static Date parse(String time,String format){
		SimpleDateFormat formatter = new SimpleDateFormat(format);
		try {
			return formatter.parse(time);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * 格式化时间 默认为yyyy-MM-dd HH:mm:ss
	 * @param time
	 * @return
	 */
	public static Date parse(String time){
		return parse(time, "yyyy-MM-dd HH:mm:ss");
	}
	
}
