package com.zjw.common.utils.endecrypt.models;

import java.security.PrivateKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;

public class CaCertificateKeyInfo extends CertificateKeyInfo {

    private final X500Name subjectName;
    private final AuthorityKeyIdentifier authorityKeyIdentifier;

    protected CaCertificateKeyInfo(CertificateKeyInfo certificateKeyInfo, X500Name subjectName,
            AuthorityKeyIdentifier authorityKeyIdentifier) {
        super(certificateKeyInfo);
        this.subjectName = subjectName;
        this.authorityKeyIdentifier = authorityKeyIdentifier;
    }

    public X500Name getSubjectName() {
        return subjectName;
    }

    public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }


    public static BuilderOnlyPrivateKey builder(PrivateKey privateKey) {
        return new BuilderOnlyPrivateKey(privateKey);
    }

    public static class BuilderOnlyPrivateKey {

        private final PrivateKey privateKey;

        public BuilderOnlyPrivateKey(PrivateKey privateKey) {
            if (privateKey == null) {
                throw new IllegalArgumentException("privateKey is null");
            }
            this.privateKey = privateKey;
        }

        public CaCertificateKeyInfo build() {
            CertificateKeyInfo certificateKeyInfo = new CertificateKeyInfo(null, privateKey, null, null);
            return new CaCertificateKeyInfo(certificateKeyInfo, null, null);
        }
    }

}
