package com.express.core.spider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.http.Header;
import org.apache.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.alibaba.fastjson.JSON;
import com.express.core.constant.ExpressConstant;
import com.express.core.http.HttpUtils;
import com.express.core.response.ResponseData;
import com.express.core.response.ResponseMsg;
import com.express.core.util.DateUtil;
import com.express.core.util.StringUtils;
import com.tgb.ccl.http.common.HttpHeader;

public class YtoSpider {
	private static final Logger log = Logger.getLogger(StoSpider.class);
	private static String URL = "http://trace.yto.net.cn:8022/TraceSimple.aspx";
	//http://www.kuaidi100.com/query?type=yuantong&postid=881443775034378914&id=1&valicode=&temp=0.31010607212566177
	//http://weixin.yto56.com.cn/Service/WaybillTrace/YTOWaybillTrace.aspx?WaybillNO=881667554913817264&Userid=oIIDzjgT1Ut6dO8uqGXOM3_pfA8U
	//http://qq.yto56.com.cn/NewWaybillTrace/WaybillTrace.aspx?WaybillNO=881667554913817264
	
	@SuppressWarnings("unchecked")
	public ResponseMsg spider_officwebsite(String number){
		ResponseMsg msg = new ResponseMsg();
		msg.setCode("yuantong");
		msg.setNumber(number);
		try {
			String body = new StringBuffer("waybillNo=").append(number).append("&validateCode=&jsessionId=").toString();
			Header[] head =HttpHeader.custom().contentType("application/x-www-form-urlencoded").referer("http://www.yto.net.cn/gw/index/").build();
			String responseText = HttpUtils.doPost(URL,body,head);
			if(StringUtils.isEmpty(responseText)){
				msg.setStatu(-2);
				msg.setStatus("接口异常");
				msg.setMessage("API请求超时");
			}else {
				Element section = Jsoup.parse(responseText).select("div[class=trace-box]").first();
				if(section==null){
					msg.setStatu(ExpressConstant.EXPRESS_NOEXIST);
					msg.setMessage("抱歉，此单号无记录。<br>如确认运单号无误，可能是快件信息尚未发出，或有延迟，请稍后再试。");
				}else {
					String status = section.select("div[class=trace-ico ]").first().select("span").text();
					msg.setStatus(status);
					if("已签收".equals(status)){
						msg.setStatu(ExpressConstant.EXPRESS_EMBRACEPARTS);
					}
					if("运送中".equals(status)){
						
					}
					if("已收件".equals(status)){
						
					}
					if("疑难".equals(status)){
						
					}
					if("用户拒签".equals(status)){
						
					}
					if("派送中".equals(status)){
						
					}
					if("退回中".equals(status)){
						
					}
					if("暂无".equals(status)){
						msg.setStatu(ExpressConstant.EXPRESS_NOEXIST);
						msg.setMessage("抱歉，此单号无记录。<br>如确认运单号无误，可能是快件信息尚未发出，或有延迟，请稍后再试。");
					}else {
						Element table = section.select("table").first();
						if(table==null){
							msg.setStatu(ExpressConstant.EXPRESS_NOEXIST);
							msg.setMessage("抱歉，此单号无记录。<br>如确认运单号无误，可能是快件信息尚未发出，或有延迟，请稍后再试。");
						}else {
							Elements tr = table.select("tr");
							String day = "";
							List<ResponseData> list = new ArrayList<ResponseData>();
							for (Element element : tr) {
								String time =element.select("td[class=time]").text();
								if(time.indexOf("-")!=-1){
									day = time.substring(0,time.indexOf(" "));
								}else {
									time = day+" "+time;
								}
								String context = element.select("td[class=data]").text();
								ResponseData data = new ResponseData();
								data.setTime(DateUtil.parse(time));
								data.setContext(context);
								list.add(data);
							}
							msg.setData(list);
						}
					}
				}
			}
			
		} catch (Exception e) {
			log.error("func[spider]-YtoSpider-excetion[{}]",e);
			msg.setNumber(number);
			msg.setStatu(-2);
			msg.setStatus("接口异常");
			msg.setMessage(e.getMessage());
			msg.setData(Collections.EMPTY_LIST);
		}
		return msg;
		
	}	
	
	/*	public ResponseMsg spider(String number){
		ResponseMsg msg = new ResponseMsg();
		msg.setCode("yuantong");
		msg.setNumber(number);
		try {
			String responseText = HttpUtils.doGet(URL+number);
			Element section = Jsoup.parse(responseText).select("div[class=demo-block]").first();
			if(section==null){
				msg.setStatu(-2);
				msg.setStatus("接口异常");
				msg.setMessage("API请求超时");				
			}else {
				
				
				
				
				String status = section.select("label[class=phonenum reok]").first().text();
				if("暂无".equals(status)){
					msg.setStatu(ExpressConstant.EXPRESS_NOEXIST);
					msg.setMessage("抱歉，此单号无记录。<br>如确认运单号无误，可能是快件信息尚未发出，或有延迟，请稍后再试。");
				}else {
					//System.out.println(section.html());
					Elements uls = section.select("ul[class~=^ui-row pad20]");
					List<ResponseData> list = new ArrayList<ResponseData>();
					for (Element element : uls) {
						ResponseData data = new ResponseData();
						data.setContext(element.select("li[class=ui-col ui-col-67 w50 ui-border-k2]").text());
						//data.setTime(element.select("li[class=ui-col ui-col-33]"));
					}
				}
				//System.out.println(responseText);
			}
			
		} catch (Exception e) {
			// TODO: handle exception
		}
		return null;
		
	}*/
	public static void main(String[] args){
		YtoSpider ytoSpider = new YtoSpider();
		ResponseMsg msg = ytoSpider.spider_officwebsite("881443775034378914");
		System.out.println(JSON.toJSONStringWithDateFormat(msg,"yyyy-MM-dd HH:mm:ss"));
	}
}
