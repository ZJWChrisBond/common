package com.zjw.common.utils.endecrypt.models;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.springframework.util.CollectionUtils;

/**
 * 证书签名请求参数
 *
 * @author zjw
 */
public class CertificationSigningRequest {

    /**
     * 证书序列号
     */
    private BigInteger serial;
    /**
     * 颁发者信息
     */
    private X500Name issuerName;

    /**
     * 颁发者私钥信息
     */
    private PrivateKey issuerPrivateKey;

    /**
     * 请求者主题信息
     */
    private X500Name reqName;

    /**
     * 请求者主题公钥信息
     */
    private PublicKey reqPublicKey;

    /**
     * 有效期开始时间
     */
    private Date notBefore;

    /**
     * 有效期截至时间
     */
    private Date notAfter;

    /**
     * 扩展
     */
    private List<Extension> extensions;

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(CertificationIssueRequest request) {
        return new Builder(request);
    }

    public X500Name getIssuerName() {
        return issuerName;
    }

    public X500Name getReqName() {
        return reqName;
    }

    public BigInteger getSerial() {
        return serial;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public PublicKey getReqPublicKey() {
        return reqPublicKey;
    }

    public PrivateKey getIssuerPrivateKey() {
        return issuerPrivateKey;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    public static class Builder {

        private X500Name issuerName;
        private X500Name reqName;
        private BigInteger serial;
        private Date notBefore;
        private Date notAfter;
        private PublicKey reqPublicKey;
        private PrivateKey issuerPrivateKey;
        private final List<Extension> extensions = new ArrayList<>();

        public Builder() {
        }

        public Builder(CertificationIssueRequest issueRequest) {
            issuerName(issueRequest.getIssuerInfo().getSubjectName()).
                    issuerPrivateKey(issueRequest.getIssuerInfo().getPrivateKey()).
                    reqPublicKey(issueRequest.getReqPublicKey()).
                    extensions(issueRequest.getExtensions());
        }

        public Builder issuerName(X500Name issuerName) {
            this.issuerName = issuerName;
            return this;
        }

        public Builder reqName(X500Name reqName) {
            this.reqName = reqName;
            return this;
        }

        public Builder serial(BigInteger serial) {
            this.serial = serial;
            return this;
        }

        public Builder notBefore(Date notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        public Builder notAfter(Date notAfter) {
            this.notAfter = notAfter;
            return this;
        }

        public Builder reqPublicKey(PublicKey reqPublicKey) {
            this.reqPublicKey = reqPublicKey;
            return this;
        }

        public Builder issuerPrivateKey(PrivateKey issuerPrivateKey) {
            this.issuerPrivateKey = issuerPrivateKey;
            return this;
        }

        public Builder extension(Extension extension) {
            this.extensions.add(extension);
            return this;
        }

        public Builder extensions(List<Extension> extensions) {
            if (!CollectionUtils.isEmpty(extensions)) {
                this.extensions.addAll(extensions);
            }
            return this;
        }

        public CertificationSigningRequest build() {
            validateParameters(issuerName, reqName, serial, notBefore, notAfter, reqPublicKey, issuerPrivateKey);
            CertificationSigningRequest request = new CertificationSigningRequest();
            request.issuerName = this.issuerName;
            request.reqName = this.reqName;
            request.serial = this.serial;
            request.notBefore = this.notBefore;
            request.notAfter = this.notAfter;
            request.reqPublicKey = this.reqPublicKey;
            request.issuerPrivateKey = this.issuerPrivateKey;
            request.extensions = Collections.unmodifiableList(this.extensions);
            return request;
        }

        private static void validateParameters(X500Name issuerName, X500Name reqName,
                BigInteger serial, Date notBefore, Date notAfter,
                PublicKey userPublicKey, PrivateKey rootPrivateKey) {
            if (issuerName == null || reqName == null || serial == null || notBefore == null || notAfter == null
                    || userPublicKey == null || rootPrivateKey == null) {
                throw new IllegalArgumentException("The parameter cannot be empty");
            }

            if (notBefore.after(notAfter)) {
                throw new IllegalArgumentException(
                        "The certificate validity start date (not Before) must be earlier than the validity end date (not After)");
            }
        }
    }
}
