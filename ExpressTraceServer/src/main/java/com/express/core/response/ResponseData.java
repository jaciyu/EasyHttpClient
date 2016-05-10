package com.express.core.response;

import java.util.Date;

public class ResponseData {
	private Date time;
	private String context;
	public Date getTime() {
		return time;
	}
	public void setTime(Date time) {
		this.time = time;
	}
	public String getContext() {
		return context;
	}
	public void setContext(String context) {
		this.context = context;
	}
	
}
