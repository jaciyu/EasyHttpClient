package com.express.core.http;

import java.util.Random;

import org.apache.http.Header;
import org.apache.http.client.HttpClient;

import com.tgb.ccl.http.common.HttpConfig;
import com.tgb.ccl.http.httpclient.HttpClientUtil;
import com.tgb.ccl.http.httpclient.builder.HCB;

/**
 * http请求工具类
 * @author yuwenjin
 * @date 2016年5月6日
 */
public class HttpUtils {
	private static int TIME_OUT = 10000;
	private static String[] USER_AGENT = {"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
		                                  ,"AppleWebKit/534.46 (KHTML,like Gecko) Version/5.1 Mobile Safari/10600.6.3 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
		                                  ,"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
		                                  ,"Mozilla/5.0 (compatible; JikeSpider; +http://shoulu.jike.com/spider.html)"
		                                  ,"Mozilla/5.0 (compatible; Yahoo! Slurp China; http://misc.yahoo.com.cn/help.html)"
		                                  ,"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)"
		                                  ,"Sogou web spider/3.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"
		                                  ,"Mozilla/5.0 (compatible; YoudaoBot/1.0; http://www.youdao.com/help/webmaster/spider/;)"
		                                  ,"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36"
		                                  ,"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
		                                  ,"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
		                                  ,"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0"
		                                  ,"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)"
		                                  ,"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
		                                  ,"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
		                                  ,"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:2.0.1) Gecko/20100101 Firefox/4.0.1"
		                                  ,"Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1"
		                                  ,"Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.8.131 Version/11.11"
		                                  ,"Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11"
		                                  ,"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11"
		                                  ,"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon 2.0)"
		                                  ,"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; TencentTraveler 4.0)"
		                                  ,"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)"
		                                  ,"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)"};
	public static String doGet(String url){
		if(url==null||url.trim().length()==0){
			return "";
		}
		try {
			int uaIndex = randNumber(0,23);
			HttpConfig  config = HttpConfig.custom();
			config.url(url);
			HttpClient client = url.startsWith("https")?HCB.custom().timeout(TIME_OUT).ssl().setUserAgent(USER_AGENT[uaIndex]).build()
					:HCB.custom().timeout(TIME_OUT).setUserAgent(USER_AGENT[uaIndex]).build();
			config.client(client);
			return HttpClientUtil.get(config);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}
	
	public static String doPost(String url,String body){
		if(url==null||url.trim().length()==0){
			return "";
		}
		try {
			int uaIndex = randNumber(0,23);
			HttpConfig  config = HttpConfig.custom();
			config.url(url);
			config.inenc(body);
			HttpClient client = url.startsWith("https")?HCB.custom().timeout(TIME_OUT).ssl().setUserAgent(USER_AGENT[uaIndex]).build()
					:HCB.custom().timeout(TIME_OUT).setUserAgent(USER_AGENT[uaIndex]).build();
			config.client(client);
			return HttpClientUtil.post(config);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";		
	}
	/**
	 * 自定义协议头，无需传ua
	 * @param url
	 * @param body
	 * @param headers
	 * @return
	 */
	public static String doPost(String url,String body,Header[] headers){
		if(url==null||url.trim().length()==0){
			return "";
		}
		try {
			int uaIndex = randNumber(0,23);
			HttpConfig  config = HttpConfig.custom();
			if(headers!=null&&headers.length>0){
				config.headers(headers);
			}
			config.body(body);
			config.url(url);
			config.inenc(body);
			HttpClient client = url.startsWith("https")?HCB.custom().timeout(TIME_OUT).ssl().setUserAgent(USER_AGENT[uaIndex]).build()
					:HCB.custom().timeout(TIME_OUT).setUserAgent(USER_AGENT[uaIndex]).build();
			config.client(client);
			return HttpClientUtil.post(config);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";		
	}
	
	public static int randNumber(int min,int max){
		Random random = new Random();
		int s = random.nextInt(max)%(max-min+1) + min;
		return s;
	}
	public static void main(String[] args){
		System.out.println(doGet("http://q1.sto.cn/chaxun/result?express_no=229855869255"));
	}
}
