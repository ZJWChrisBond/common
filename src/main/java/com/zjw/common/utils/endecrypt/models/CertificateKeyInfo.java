package com.zjw.common.utils.endecrypt.models;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateKeyInfo extends CertificateInfo {

    private final PrivateKey privateKey;

    public CertificateKeyInfo(X509Certificate x509Certificate, PrivateKey privateKey, Date notBefore, Date notAfter) {
        super(x509Certificate, notBefore, notAfter);
        this.privateKey = privateKey;
    }

    public CertificateKeyInfo(CertificateKeyInfo certificateKeyInfo) {
        super(certificateKeyInfo.getX509Certificate(), certificateKeyInfo.getNotBefore(),
                certificateKeyInfo.getNotAfter());
        this.privateKey = certificateKeyInfo.getPrivateKey();
    }

    public CertificateKeyInfo(CertificateInfo certificateInfo, PrivateKey privateKey) {
        super(certificateInfo.getX509Certificate(), certificateInfo.getNotBefore(),
                certificateInfo.getNotAfter());
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

}
