package com.express.core.constant;

public final class ExpressConstant {
	 /**
	  * -1:无记录
	  * 0：在途，即货物处于运输过程中；
	  * 1：揽件，货物已由快递公司揽收并且产生了第一条跟踪信息；
	  * 2：疑难，货物寄送过程出了问题；
	  * 3：签收，收件人已签收；
	  * 4：退签，即货物由于用户拒签、超区等原因退回，而且发件人已经签收；
	  * 5：派件，即快递正在进行同城派件；
	  * 6：退回，货物正处于退回发件人的途中；*/
	public static int EXPRESS_NOEXIST = -1;//查询的快递无记录，不存在
	public static int EXPRESS_ONWAY = 0;
	public static int EXPRESS_EMBRACEPARTS = 1;
	public static int EXPRESS_DIFFICULT = 2;
	public static int EXPRESS_RECEIVE = 3;
	public static int EXPRESS_REJECT = 4;
	public static int EXPRESS_SEND = 5;
	public static int EXPRESS_RETURN = 6;
	
	public static String getStsteText(int state){
		switch (state) {
		case 0:return "运送中";
		case 1:return "已收件";
		case 2:return "疑难";
		case 3:return "已签收";
		case 4:return "用户拒签";
		case 5:return "派送中";
		case 6:return "退回中";
		default:return "";
		}
	}
	
}
