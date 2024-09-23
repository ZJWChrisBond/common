package com.zjw.common.utils.endecrypt;

import com.zjw.common.utils.endecrypt.models.CertificationSigningRequest;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.util.CollectionUtils;

/**
 * 证书生成器
 *
 * @author zjw
 */
public class CertGeneratorUtils {

    /**
     * 根据如下参数获取对应base64编码格式的证书文件字符串 issuerName 与 reqName 对象是同一个则认为生成的是CA证书
     */
    public static X509Certificate buildCert(ContentSigner signer, CertificationSigningRequest request)
            throws CertificateException, IOException, NoSuchAlgorithmException {
        JcaX509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
                request.getIssuerName(), request.getSerial(), request.getNotBefore(), request.getNotAfter(),
                request.getReqName(), request.getReqPublicKey());

        if (!CollectionUtils.isEmpty(request.getExtensions())) {
            for (Extension extension : request.getExtensions()) {
                x509v3CertificateBuilder.addExtension(extension);
            }
        }

        // 签发者 与 使用者 信息一致则是CA证书生成，开展增加CA标识
        if (request.getIssuerName() == request.getReqName()) {
            x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            x509v3CertificateBuilder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier subjectKeyIdentifier = utils.createSubjectKeyIdentifier(request.getReqPublicKey());
        x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(x509v3CertificateBuilder.build(signer));
    }

    /**
     * rsa
     */
    public static String buildRSACertStr(CertificationSigningRequest request)
            throws OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
        return CertUtil.genCert(buildRSACert(request));
    }

    /**
     * rsa
     */
    public static X509Certificate buildRSACert(CertificationSigningRequest request)
            throws OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
        //签名的工具
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSA").setProvider("BC")
                .build(request.getIssuerPrivateKey());
        return buildCert(signer, request);
    }

    /**
     * sm2
     */
    public static String buildSM2CertStr(CertificationSigningRequest request)
            throws OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
        return CertUtil.genCert(buildSM2Cert(request));
    }

    /**
     * sm2
     */
    public static X509Certificate buildSM2Cert(CertificationSigningRequest request)
            throws OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
        //签名的工具
        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(request.getIssuerPrivateKey());
        return buildCert(signer, request);
    }

    private CertGeneratorUtils() {
    }
}
