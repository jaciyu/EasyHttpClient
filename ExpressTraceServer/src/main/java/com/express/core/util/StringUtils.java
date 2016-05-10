package com.express.core.util;

public final class StringUtils {
	public static boolean isEmpty(String context){
		if(context!=null&&context.trim().length()>0){
			return false;
		}else {
			return true;
		}
	}
}
