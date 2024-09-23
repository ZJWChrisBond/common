package com.zjw.common.utils.endecrypt.models;

import com.zjw.common.lang.Try;
import com.zjw.common.utils.endecrypt.CertUtil;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

public class CertificateInfo {

    private String certPem;
    private final X509Certificate x509Certificate;
    private final Date notBefore;
    private final Date notAfter;

    public CertificateInfo(X509Certificate x509Certificate, Date notBefore, Date notAfter) {
        Try.rethrow(() -> {
            if (null != x509Certificate) {
                this.certPem = CertUtil.genCert(x509Certificate);
            }
        });
        this.x509Certificate = x509Certificate;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public String getCertPem() {
        return certPem;
    }

    public X500Name buildSubjectName() {
        return Try.rethrow(() -> new JcaX509CertificateHolder(x509Certificate).getSubject());
    }

    public X500Name buildIssuerName() {
        return Try.rethrow(() -> new JcaX509CertificateHolder(x509Certificate).getIssuer());
    }

    public String buildCnName() {
        RDN[] rdNs = buildSubjectName().getRDNs();
        for (RDN rdn : rdNs) {
            if (rdn.getFirst().getType().equals(BCStyle.CN)) {
                return rdn.getFirst().getValue().toString();
            }
        }
        return null;
    }

    public AuthorityKeyIdentifier buildAuthorityKeyIdentifier()
            throws NoSuchAlgorithmException, CertificateEncodingException {
        return new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(x509Certificate);
    }

}
