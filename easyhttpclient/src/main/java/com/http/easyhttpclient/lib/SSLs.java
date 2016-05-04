package com.http.easyhttpclient.lib;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContexts;

/**
* SSL配置
* @author jaciyu
* @date 2016年5月4日
*/
public class SSLs {
    private static final SSLHandler simpleVerifier = new SSLHandler();
	private static SSLSocketFactory sslFactory ;
	private static SSLConnectionSocketFactory sslConnFactory ;
	private static SSLIOSessionStrategy sslIOSessionStrategy ;
	private static SSLs sslutil = new SSLs();
	private SSLContext sc;
	
	public static SSLs getInstance(){
		return sslutil;
	}
	public static SSLs custom(){
		return new SSLs();
	}

    // 重写X509TrustManager类的三个方法,信任服务器证书
    private static class SSLHandler implements  X509TrustManager, HostnameVerifier{
		
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
		
		@Override
		public void checkServerTrusted(X509Certificate[] chain,String authType) throws CertificateException {
		}
		
		@Override
		public void checkClientTrusted(X509Certificate[] chain,String authType) throws CertificateException {
		}

		@Override
		public boolean verify(String paramString, SSLSession paramSSLSession) {
			return true;
		}
	};
    
	// 信任主机
    public static HostnameVerifier getVerifier() {
        return simpleVerifier;
    }
    
    public synchronized SSLSocketFactory getSSLSF(){
        if (sslFactory != null)
            return sslFactory;
		try {
			SSLContext sc = getSSLContext();
			sc.init(null, new TrustManager[] { simpleVerifier }, null);
			sslFactory = sc.getSocketFactory();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		}
        return sslFactory;
    }
    
    public synchronized SSLConnectionSocketFactory getSSLCONNSF(){
    	if (sslConnFactory != null)
    		return sslConnFactory;
    	try {
	    	SSLContext sc = getSSLContext();
	    	sc.init(null, new TrustManager[] { simpleVerifier }, null);
	    	sslConnFactory = new SSLConnectionSocketFactory(sc, simpleVerifier);
		} catch (KeyManagementException e) {
			e.printStackTrace();
		}
    	return sslConnFactory;
    }
    
    public synchronized SSLIOSessionStrategy getSSLIOSS(){
    	if (sslIOSessionStrategy != null)
    		return sslIOSessionStrategy;
		try {
			SSLContext sc = getSSLContext();
			sc.init(null, new TrustManager[] { simpleVerifier }, null);
			sslIOSessionStrategy = new SSLIOSessionStrategy(sc, simpleVerifier);
		} catch (KeyManagementException e) {
			e.printStackTrace();
		}
    	return sslIOSessionStrategy;
    }
    /**
     * 
     * @param keyStorePath  自签名证书路径
     * @param keyStorepass  自签名证书密码
     * @return
     * @author jaciyu
     */
    public SSLs customSSL(String keyStorePath, String keyStorepass){
    	FileInputStream instream =null;
    	KeyStore trustStore = null; 
		try {
			trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			instream = new FileInputStream(new File(keyStorePath));
	     	trustStore.load(instream, keyStorepass.toCharArray());
            // 相信自己的CA和所有自签名的证书
	     	sc= SSLContexts.custom().loadTrustMaterial(trustStore, new TrustSelfSignedStrategy()) .build();	
		} catch (Exception  e) {
			e.printStackTrace();
		}finally{
			try {
				instream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return this;
    }
    /**
     * 默认TLSv1.2
     * @return
     * @author jaciyu
     */
    public SSLContext getSSLContext(){
    	return getSSLContext("TLSv1.2");
    }
    /**
     * 
     * @param protocol 目前在用的SSL协议主要有5个版本分别是SSLv2、SSLv3、TLSv1.0、TLSv1.1、TLSv1.2,由于SSL漏洞原因有些网站可能不支持SSLv2、SSLv3，建议使用TLSv1.2需要JDK1.7以上版本
     * @return
     * @author jaciyu
     */
    public SSLContext getSSLContext(String protocol){
    	try {
    		if(protocol==null||protocol.trim().length()==0){
    			protocol = "TLSv1.2";
    		}
    		sc = SSLContext.getInstance(protocol);
			return sc;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
    	return sc;
    }      
}
