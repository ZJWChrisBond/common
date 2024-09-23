package com.zjw.common.utils.endecrypt.models;

import com.sun.deploy.security.CertType;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * 证书颁发请求
 *
 * @author zjw
 */
public class CertificationIssueRequest {

    /**
     * 请求者名称
     */
    private String cn;

    /**
     * 请求者主题公钥信息
     */
    private PublicKey reqPublicKey;

    /**
     * CA证书信息
     */
    private CaCertificateKeyInfo issuerInfo;

    /**
     * 是否是自签名CA证书
     */
    private Boolean selfSigningCa = false;

    /**
     * 证书类型
     */
    private CertType certType;

    /**
     * 扩展
     */
    private List<Extension> extensions;

    /**
     * 有效期
     */
    private Duration effectPeriod;

    public static Builder builder() {
        return new Builder();
    }

    private CertificationIssueRequest() {
    }

    public String getCn() {
        return cn;
    }

    public PublicKey getReqPublicKey() {
        return reqPublicKey;
    }

    public CaCertificateKeyInfo getIssuerInfo() {
        return issuerInfo;
    }

    public CertType getCertType() {
        return certType;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    public Boolean isSelfSignedCa() {
        return selfSigningCa;
    }

    public Duration getEffectPeriod() {
        return effectPeriod;
    }

    public static class Builder {

        private String cn;
        private PublicKey reqPublicKey;
        private CaCertificateKeyInfo issuerInfo;
        private Boolean selfSigningCa;
        private CertType certType;
        private Duration effectPeriod;
        private final List<Extension> extensions = new ArrayList<>();

        public CertificationIssueRequest build() {
            if (Boolean.TRUE.equals(selfSigningCa)) {
                Assert.notNull(effectPeriod, "effectPeriod must not be null");
            }
            Assert.notNull(issuerInfo, "issuerInfo must not be null");
            Assert.hasText(cn, "cn must not be empty");
            Assert.notNull(reqPublicKey, "reqPublicKey must not be null");
            CertificationIssueRequest req = new CertificationIssueRequest();
            req.cn = cn;
            req.reqPublicKey = reqPublicKey;
            req.issuerInfo = issuerInfo;
            req.selfSigningCa = selfSigningCa;
            req.extensions = Collections.unmodifiableList(this.extensions);
            req.certType = certType;
            req.effectPeriod = effectPeriod;
            return req;
        }

        public Builder setCn(String cn) {
            this.cn = cn;
            return this;
        }

        public Builder setReqPublicKey(PublicKey reqPublicKey) {
            this.reqPublicKey = reqPublicKey;
            return this;
        }

        public Builder setIssuerInfo(CaCertificateKeyInfo issuerInfo) {
            this.issuerInfo = issuerInfo;
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

        public Builder certType(CertType certType) {
            this.certType = certType;
            return this;
        }

        public Builder selfSignedCa() {
            this.selfSigningCa = Boolean.TRUE;
            return this;
        }

        public Builder effectPeriod(Duration effectPeriod) {
            this.effectPeriod = effectPeriod;
            return this;
        }

        public String getCn() {
            return cn;
        }

        public PublicKey getReqPublicKey() {
            return reqPublicKey;
        }

        public CaCertificateKeyInfo getIssuerInfo() {
            return issuerInfo;
        }

        public Boolean getSelfSigningCa() {
            return selfSigningCa;
        }

        public CertType getCertType() {
            return certType;
        }

        public List<Extension> getExtensions() {
            return extensions;
        }

        public Duration getEffectPeriod() {
            return effectPeriod;
        }


    }
}
