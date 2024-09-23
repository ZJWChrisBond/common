package com.zjw.common.utils.encrypt;

import com.zjw.common.utils.endecrypt.models.CertificationSigningRequest;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;

public class CertificationSigningRequestUtils {

    public static CertificationSigningRequest build(X500Name issuerName, X500Name reqName,
            BigInteger serial,
            Date notBefore, Date notAfter, PublicKey userPublicKey, PrivateKey issuerPrivateKey,
            List<Extension> extensions) {
        return CertificationSigningRequest.builder().serial(serial)
                .issuerName(issuerName).issuerPrivateKey(issuerPrivateKey)
                .reqName(reqName).reqPublicKey(userPublicKey)
                .notBefore(notBefore).notAfter(notAfter).extensions(extensions)
                .build();
    }

}
