package com.zjw.common.utils.net;

import javax.net.ssl.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Ssl工具
 *
 * @author zjw
 */
public class SslUtil {


    /**
     * 忽略HTTPS请求的SSL证书
     */
    public static void ignoreSsl() throws Exception {
        HostnameVerifier hv = (urlHostName, session) -> true;
        trustAllHttpsCertificates();
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
    }

    private static void trustAllHttpsCertificates() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[1];
        TrustManager tm = new CustomTrustManager();
        trustAllCerts[0] = tm;
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    static class CustomTrustManager implements TrustManager, X509TrustManager {

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public boolean isServerTrusted() {
            return true;
        }

        public boolean isClientTrusted() {
            return true;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        }
    }

    private SslUtil() {

    }
}
