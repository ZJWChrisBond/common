package com.zjw.common.utils.endecrypt;

import com.zjw.common.lang.Try;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * RSA 证书生成工具
 */
public class CertUtil {

    private static final String CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String CERTIFICATE_FOOTER = "-----END CERTIFICATE-----";

    public static final String KEY_ALGORITHM = "RSA";

    public static final String PUBLIC_KEY = "RSAPublicKey";
    public static final String PRIVATE_KEY = "RSAPrivateKey";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成公、私钥对
     */
    @SneakyThrows
    public static Pair<RSAPublicKey, RSAPrivateKey> genKey() {
        //通过对象 KeyPairGenerator 获取对象KeyPair
        KeyPair keyPair = RSAUtils.generateKeyPair();

        //通过对象 KeyPair 获取RSA公私钥对象RSAPublicKey RSAPrivateKey
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        //公私钥对象存入Pair中
        return Pair.of(publicKey, privateKey);
    }

    /**
     * X509Certificate 对象封装
     *
     * @param serialNumber 证书编号
     * @param notBefore    起始日期
     * @param notAfter     解之日期
     * @param issuer       发行者
     * @param reqSubject   请求者主体
     * @param privateKey   发行者私钥
     * @param publicKey    请求者公钥
     */
    public static X509Certificate genX509Certificate(BigInteger serialNumber, Date notBefore, Date notAfter,
            X500Name issuer, X500Name reqSubject, PrivateKey privateKey, PublicKey publicKey)
            throws OperatorCreationException, IOException, CertificateException {
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter,
                reqSubject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");

        if (issuer == reqSubject) {
            BasicConstraints constraint = new BasicConstraints(1);
            certBuilder.addExtension(Extension.basicConstraints, false, constraint);
        }

        ContentSigner signer = builder.build(privateKey);
        byte[] certBytes = certBuilder.build(signer).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(certBytes));
        return certificate;
    }


    /**
     * 生成PFX证书文件
     *
     * @param certificate 证书 建议 CertUtil#genX509Certificate(java.math.BigInteger, java.util.Date, java.util.Date,
     *                    org.bouncycastle.asn1.x500.X500Name, org.bouncycastle.asn1.x500.X500Name,
     *                    java.security.PrivateKey, java.security.PublicKey)()
     * @param privateKey  请求者私钥
     * @param passWord    pfx生成后的密码
     * @param certPath    pfx存储路径
     */
    public static void genPfx(Certificate certificate, PrivateKey privateKey, String passWord, String certPath)
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, passWord.toCharArray());
        store.setKeyEntry("", privateKey, passWord.toCharArray(), new Certificate[]{certificate});

        FileOutputStream fout = new FileOutputStream(certPath);
        store.store(fout, passWord.toCharArray());
        fout.close();
    }

    /**
     * 获取 pfx 对应的公私钥以及证书Certificate 解析
     *
     * @param fileInputStream pxf读取的文件输入流
     * @param passWord        pfx文件对应的密码
     */
    public static HashMap<Object, Object> pfxAnalze(FileInputStream fileInputStream, String passWord)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] nPassword = passWord.toCharArray();
        ks.load(fileInputStream, nPassword);
        fileInputStream.close();
        Enumeration<String> enums = ks.aliases();
        String keyAlias = null;
        if (enums.hasMoreElements()) {
            keyAlias = enums.nextElement();
        }
        PrivateKey privateKey = (PrivateKey) ks.getKey(keyAlias, nPassword);
        Certificate cert = ks.getCertificate(keyAlias);
        PublicKey pubkey = cert.getPublicKey();
        HashMap<Object, Object> hashMap = new HashMap(3);
        hashMap.put(PrivateKey.class, privateKey);
        hashMap.put(PublicKey.class, pubkey);
        hashMap.put(Certificate.class, cert);
        return hashMap;
    }

    /**
     * 获取CSR包含的公钥 10进制
     *
     * @param pkcs10CertificationRequest 参考 CertUtil#csrAnalyze(java.lang.String)
     */
    public static PublicKey csrGetPublicKeyByX509(PKCS10CertificationRequest pkcs10CertificationRequest)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                pkcs10CertificationRequest.getSubjectPublicKeyInfo().toASN1Primitive().getEncoded());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec);
        return publicKey;
    }

    /**
     * 获取包含的公钥 16进制
     *
     * @param pkcs10CertificationRequest
     */
    public static PublicKey csrGetPublicKeyByPKCS(PKCS10CertificationRequest pkcs10CertificationRequest)
            throws NoSuchAlgorithmException, InvalidKeyException {
        JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(
                pkcs10CertificationRequest);
        X500Name subject = jcaPKCS10CertificationRequest.getSubject();
        PublicKey publicKey = jcaPKCS10CertificationRequest.getPublicKey();
        return publicKey;
    }

    /**
     * 根据csr文件字符串生成对应的PKCS10CertificationRequest对象
     *
     * @param csrStr
     */
    public static PKCS10CertificationRequest csrAnalyze(String csrStr) throws IOException {
        if (!csrStr.startsWith("-----BEGIN CERTIFICATE REQUEST-----") || !csrStr.endsWith(
                "-----END CERTIFICATE REQUEST-----")) {
            throw new IOException("csr 信息不合法");
        }
        csrStr = csrStr.replace("-----BEGIN CERTIFICATE REQUEST-----" + "\n", "");
        csrStr = csrStr.replace("\n" + "-----END CERTIFICATE REQUEST-----", "");
        byte[] bArray = Base64.getDecoder().decode(csrStr);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(bArray);
        System.out.println(csr);
        return csr;
    }

    /**
     * 读取jks文件输入流中的私钥
     *
     * @param inputStream jks文件输入流 FileInputStream
     * @param password    jks 对应的密码
     */
    public static Map<Class<?>, Object> jksAnalyze(InputStream inputStream, String password)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("jks");
        keystore.load(inputStream, password.toCharArray());
        Enumeration<String> enumeration = keystore.aliases();
        String keyAlias = null;
        if (enumeration.hasMoreElements()) {
            keyAlias = enumeration.nextElement();
        }
        PrivateKey privateKey = (PrivateKey) keystore.getKey(keyAlias, password.toCharArray());
        Certificate certificate = keystore.getCertificate(keyAlias);

        Map<Class<?>, Object> hashMap = new HashMap<>();
        hashMap.put(PrivateKey.class, privateKey);
        hashMap.put(Certificate.class, certificate);

        return hashMap;
    }

    /**
     * cert cer后缀 证书字符串转对象
     *
     * @param certStr
     */
    public static X509Certificate certAnalyze(String certStr)
            throws CertificateException, NoSuchProviderException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certStr.getBytes()));
    }

    public static X509Certificate certAnalyze(byte[] cert)
            throws CertificateException, NoSuchProviderException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(cert));
    }


    /**
     * 生成 CSR 请求文件
     *
     * @param reqName        请求者主体信息
     * @param userPublicKey  用户公钥
     * @param userPrivateKey 用户私钥
     */
    public static String csrBuilder(X500Name reqName, PublicKey userPublicKey, PrivateKey userPrivateKey)
            throws OperatorCreationException, IOException {

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(reqName, userPublicKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner csrSigner = csBuilder.build(userPrivateKey);
        PKCS10CertificationRequest csr = p10Builder.build(csrSigner);

        //处理证书 ANS.I DER 编码 =》 String Base64编码
        String cerFormat = Base64.getEncoder().encodeToString(csr.getEncoded());

        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE REQUEST-----" + "\n");
        sb.append(cerFormat).append("\n");
        sb.append("-----END CERTIFICATE REQUEST-----");
        return sb.toString();
    }


    /**
     * Certificate ==》 CertStr
     *
     * @param certificate
     */
    public static String genCert(Certificate certificate) throws IOException, CertificateEncodingException {
        //处理证书 ANS.I DER 编码 =》 String Base64编码

        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----" + "\n");
        sb.append(Base64.getEncoder().encodeToString(certificate.getEncoded())).append("\n");
        sb.append("-----END CERTIFICATE-----");
        return sb.toString();
    }

    /**
     * 添加PKCS8格式
     */
    public static String wrapKeyPem(PrivateKey privateKey) {
        return "-----BEGIN PRIVATE KEY-----" + "\n" + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n"
                + "-----END PRIVATE KEY-----";
    }


    /**
     * 颁发者 或者 申请者 信息封装
     *
     * @param CN 公用名 对于 SSL 证书，一般为网站域名；而对于代码签名证书则为申请单位名称；而对于客户端证书则为证书申请者的姓名
     * @param O  组织 对于 SSL 证书，一般为网站域名；而对于代码签名证书则为申请单位名称；而对于客户端单位证书则为证书申请者所在单位名称；
     * @param L  城市
     * @param ST 省/ 市/ 自治区名
     * @param C  国家
     * @param OU 组织单位/显示其他内容
     */
    public static X500Name getX500Name(String CN, String O, String L, String ST, String C, String OU) {
        X500NameBuilder rootIssueMessage = new X500NameBuilder(BCStrictStyle.INSTANCE);
        rootIssueMessage.addRDN(BCStyle.CN, CN);
        if (O != null) {
            rootIssueMessage.addRDN(BCStyle.O, O);
        }
        if (L != null) {
            rootIssueMessage.addRDN(BCStyle.L, L);
        }
        if (ST != null) {
            rootIssueMessage.addRDN(BCStyle.ST, ST);
        }
        if (C != null) {
            rootIssueMessage.addRDN(BCStyle.C, C);
        }
        if (OU != null) {
            rootIssueMessage.addRDN(BCStyle.OU, OU);
        }
        return rootIssueMessage.build();
    }

    /**
     * 封装对应的私钥通过下列参数
     *
     * @param radix              参数进制
     * @param publicMudulusStr   公钥 mudulus
     * @param privateExponentStr 私钥 expoent
     */
    public static PrivateKey getPrivateKey(int radix, String publicMudulusStr, String privateExponentStr)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        BigInteger privateModulus = new BigInteger(publicMudulusStr, radix);
        BigInteger privateExponent = new BigInteger(privateExponentStr, radix);
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(privateModulus, privateExponent);
        PrivateKey rootPrivateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);
        return rootPrivateKey;
    }

    /**
     * 封装对应的公钥通过下列参数
     *
     * @param radix            参数进制
     * @param publicMudulusStr 公钥mudulus
     * @param publicExpoentStr 公钥expoent
     */
    public static PublicKey getPublicKey(int radix, String publicMudulusStr, String publicExpoentStr)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        BigInteger publicModulus = new BigInteger(publicMudulusStr, radix);
        BigInteger publicExponent = new BigInteger(publicExpoentStr, radix);
        RSAPublicKeySpec keySpecPublic = new RSAPublicKeySpec(publicModulus, publicExponent);
        PublicKey publicKey = keyFactory.generatePublic(keySpecPublic);
        return publicKey;
    }

    /**
     * 判断是否是 CA 证书
     */
    public static boolean isCACertificate(X509Certificate certificate) {
        // 检查证书是否是 CA
        return certificate.getBasicConstraints() != -1;
    }


    /**
     * 验证私钥和证书是否匹配
     */
    public static boolean validateKeyPair(PrivateKey privateKey, X509Certificate certificate) {
        return Try.error(false, () -> {
            // 用私钥签名一些数据
            byte[] data = "test data".getBytes();

            CertStandard certStandard = determineCertStandard(certificate);
            Signature signature;
            if (certStandard == CertStandard.GM) {
                signature = Signature.getInstance("SHA256withSM2", "BC");
            } else {
                signature = Signature.getInstance("SHA256withRSA");
            }

            signature.initSign(privateKey);
            signature.update(data);
            byte[] signedData = signature.sign();

            // 用证书中的公钥验证签名
            signature.initVerify(certificate.getPublicKey());
            signature.update(data);
            return signature.verify(signedData);
        });
    }

    /**
     * 获取证书标准
     */
    public static CertStandard determineCertStandard(X509Certificate certificate) {
        String sigAlgName = certificate.getSigAlgName();
        String publicKeyAlgorithm = certificate.getPublicKey().getAlgorithm();
        if ("EC".equals(publicKeyAlgorithm) && sigAlgName.contains("SM2")) {
            return CertStandard.GM;
        } else if ("RSA".equals(publicKeyAlgorithm)) {
            return CertStandard.STANDARD;
        } else {
            throw new IllegalArgumentException("unsupported cert standard: " + publicKeyAlgorithm + " " + sigAlgName);
        }
    }

    /**
     * 解析证书内容
     */
    public static Map<String, Object> analyzeCertContent(byte[] cert)
            throws CertificateException, NoSuchProviderException {
        X509Certificate x509Cert = certAnalyze(cert);

        Map<String, Object> map = new HashMap<>();
        Date notAfter = x509Cert.getNotAfter();
        Date notBefore = x509Cert.getNotBefore();
        map.put("notAfter", notAfter);
        map.put("notBefore", notBefore);

        JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(x509Cert);
        String subjectDN = certificateHolder.getSubject().toString();
        String issuerDN = certificateHolder.getIssuer().toString();
        map.put("subjectDN", subjectDN);
        map.put("issuerDN", issuerDN);
        return map;
    }

    public enum CertStandard {

        /**
         * 标准
         */
        STANDARD("S"),

        /**
         * 国密
         */
        GM("GM");

        private final String value;

        CertStandard(String value) {
            this.value = value;
        }


    }

}
