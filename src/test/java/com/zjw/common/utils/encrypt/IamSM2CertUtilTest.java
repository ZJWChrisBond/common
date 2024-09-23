package com.zjw.common.utils.encrypt;

import static com.zjw.common.utils.endecrypt.CertGeneratorUtils.buildSM2CertStr;
import static com.zjw.common.utils.endecrypt.CertUtil.getX500Name;
import static com.zjw.common.utils.endecrypt.CertUtil.wrapKeyPem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertNotNull;

import com.zjw.common.utils.endecrypt.CertUtil;
import com.zjw.common.utils.endecrypt.PrivateKeyUtils;
import com.zjw.common.utils.endecrypt.gm.SM2EncryptUtils;
import com.zjw.common.utils.endecrypt.gm.SM2Utils;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

/**
 * sm2 utils
 */
public class IamSM2CertUtilTest {

    private static PublicKey ROOT_PUBLIC_KEY;
    private static PrivateKey ROOT_PRIVATE_KEY;

    static {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair = null;
        try {
            keyPair = PrivateKeyUtils.sm2GenerateKeyPair();
            ROOT_PUBLIC_KEY = keyPair.getPublic();
            ROOT_PRIVATE_KEY = keyPair.getPrivate();
        } catch (Exception e) {
        }
    }

    /**
     * 签发CA证书
     */
    @Test
    public void genCaCertTest() throws Exception {
        String certStr = CertUtil.genCert(buildCaCert());
        System.out.println("\n" + certStr);

        System.out.println("\n" + wrapKeyPem(ROOT_PRIVATE_KEY));
    }

    public X509Certificate buildCaCert() throws Exception {
        return buildCaCert(getX500Name("iam", "bingo", "gz", "gd", "CN", "bingo"));
    }

    public X509Certificate buildCaCert(X500Name issuerName) throws Exception {
        // 证书序列号
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        //证书有 起始日期 与 结束日期
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date notBefore = sdf.parse("2023-11-01 10:00:00");
        Date notAfter = sdf.parse("2124-11-01 10:00:00");

        //构建证书的build
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier authorityKeyIdentifier = utils.createAuthorityKeyIdentifier(ROOT_PUBLIC_KEY);
        Extension extension = Extension.create(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        System.out.println(Base64.getEncoder().encodeToString(authorityKeyIdentifier.getEncoded()));

        return CertUtil.certAnalyze(
                buildSM2CertStr(
                        CertificationSigningRequestUtils.build(issuerName, issuerName, serial, notBefore, notAfter,
                                ROOT_PUBLIC_KEY, ROOT_PRIVATE_KEY,
                                Collections.singletonList(extension))));
    }


    public X509Certificate buildCaCert(X500Name issuerName, List<Extension> extensions) throws Exception {
        // 证书序列号
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        //证书有 起始日期 与 结束日期
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date notBefore = sdf.parse("2023-11-01 10:00:00");
        Date notAfter = sdf.parse("2124-11-01 10:00:00");

        return CertUtil.certAnalyze(
                buildSM2CertStr(
                        CertificationSigningRequestUtils.build(issuerName, issuerName, serial, notBefore, notAfter,
                                ROOT_PUBLIC_KEY, ROOT_PRIVATE_KEY,
                                extensions)));
    }

    /**
     * 签发网关的CA证书
     */
    @Test
    public void genGatewayCertsTest() throws Exception {
        X500Name rootX500Name = getX500Name("zta-gateway-root", "bingo", "gz", "gd", "CN", "bingo");
        X509Certificate rootCert = buildCaCert(rootX500Name);
        String certStr = CertUtil.genCert(rootCert);
        System.out.println("ca:\n");
        System.out.println("\n" + certStr + "\n");

        // sign证书 基本使用者
        X500Name reqName = getX500Name("zta-gateway-sign", "bingo", "gz", "gd", "CN", "bingo");

        GeneralName generalName = new GeneralName(GeneralName.dNSName, "zt-gateway");
        GeneralNames subjectAltNames = new GeneralNames(generalName);
        Extension subjectAlternativeNameEx = Extension.create(Extension.subjectAlternativeName, false, subjectAltNames);

        X509Certificate signCert = buildSignCert(rootX500Name, reqName, subjectAlternativeNameEx);
        String signCertStr = CertUtil.genCert(signCert);
        System.out.println("signCert:\n");
        System.out.println("\n" + signCertStr + "\n");

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        testCertificateValidation(cf, rootCert, signCert);

        // enc证书 基本使用者
        reqName = getX500Name("zta-gateway-enc", "bingo", "gz", "gd", "CN", "bingo");
        X509Certificate encCert = buildEncCert(rootX500Name, reqName, subjectAlternativeNameEx);
        String encCertStr = CertUtil.genCert(encCert);
        System.out.println("encCert:\n");
        System.out.println("\n" + encCertStr + "\n");

        testCertificateValidation(cf, rootCert, encCert);
    }


    /**
     * 生成ENC证书 签发证书的颁发者信息 要与生成ca证书时的签发信息一致，不然会出错。证书链验证不过。
     */
    @Test
    void genEncCertTest() throws Exception {
        String certStr = CertUtil.genCert(buildEncCert());
        System.out.println("\n" + certStr);
    }

    private X509Certificate buildEncCert() throws Exception {
        //根证书Issue基本信息
        X500Name issuerName = getX500Name("iam", "bingo", "gz", "gd", "CN", "bingo");
        // 用户证书 基本使用者
        X500Name reqName = getX500Name("kid-1", "bingo", "gz", "gd", "CN", "bingo");
        return buildEncCert(issuerName, reqName);
    }

    private X509Certificate buildEncCert(X500Name issuerName, X500Name reqName, Extension... es) throws Exception {
        // 证书序列号
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        //证书 起始日期 与 结束日期
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date notBefore = sdf.parse("2023-08-02 00:00:00");
        Date notAfter = sdf.parse("2098-07-01 10:00:00");

        KeyPair keyPair = PrivateKeyUtils.sm2GenerateKeyPair();

        PrivateKey userPrivateKey = keyPair.getPrivate();
        System.out.println("encPrivate:\n");
        System.out.println(wrapKeyPem(userPrivateKey) + "\n");

        PublicKey userPublicKey = keyPair.getPublic();

        ArrayList<Extension> extensions = new ArrayList<>();

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier authorityKeyIdentifier = utils.createAuthorityKeyIdentifier(ROOT_PUBLIC_KEY);

        System.out.println(Base64.getEncoder().encodeToString(authorityKeyIdentifier.getEncoded()));

        extensions.add(Extension.create(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier));

        extensions.add(Extension.create(Extension.keyUsage, false,
                new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.keyEncipherment | KeyUsage.keyAgreement)));

        extensions.addAll(Arrays.asList(es));

        //构建证书的build
        return CertUtil.certAnalyze(
                buildSM2CertStr(CertificationSigningRequestUtils.build(issuerName, reqName, serial, notBefore, notAfter,
                        userPublicKey, ROOT_PRIVATE_KEY,
                        extensions)));
    }

    /**
     * 生成Sign证书 签发证书的颁发者信息 要与生成ca证书时的签发信息一致，不然会出错。证书链验证不过。
     */
    @Test
    void genSignCertTest() throws Exception {
        String certStr = CertUtil.genCert(buildEncCert());
        System.out.println("\n" + certStr);
    }

    private X509Certificate buildSignCert(X500Name issuerName, X500Name reqName, Extension... es) throws Exception {
        // 证书序列号
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        //证书 起始日期 与 结束日期
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date notBefore = sdf.parse("2023-08-02 00:00:00");
        Date notAfter = sdf.parse("2098-07-01 10:00:00");

        KeyPair keyPair = PrivateKeyUtils.sm2GenerateKeyPair();

        PublicKey userPublicKey = keyPair.getPublic();
        PrivateKey userPrivateKey = keyPair.getPrivate();
        System.out.println("signPrivate:\n");
        System.out.println(wrapKeyPem(userPrivateKey) + "\n");

        ArrayList<Extension> extensions = new ArrayList<>();

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier authorityKeyIdentifier = utils.createAuthorityKeyIdentifier(ROOT_PUBLIC_KEY);

        System.out.println(Base64.getEncoder().encodeToString(authorityKeyIdentifier.getEncoded()));

        extensions.add(Extension.create(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier));

        extensions.add(Extension.create(Extension.keyUsage, false,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation)));
        extensions.addAll(Arrays.asList(es));

        //构建证书的build
        return CertUtil.certAnalyze(
                buildSM2CertStr(CertificationSigningRequestUtils.build(issuerName, reqName, serial, notBefore, notAfter,
                        userPublicKey, ROOT_PRIVATE_KEY,
                        extensions)));
    }

    private X509Certificate buildSignCert() throws Exception {
        //根证书Issue基本信息
        X500Name issuerName = getX500Name("iam", "bingo", "gz", "gd", "CN", "bingo");
        // 用户证书 基本使用者
        X500Name reqName = getX500Name("kid-1", "bingo", "gz", "gd", "CN", "bingo");
        return buildSignCert(issuerName, reqName);
    }


    String rootTemCert =
            "-----BEGIN CERTIFICATE-----\n" + "MIIB3DCCAYKgAwIBAgIBADAKBggqgRzPVQGDdTBFMQswCQYDVQQGEwJBQTELMAkG\n"
                    + "A1UECAwCQkIxCzAJBgNVBAoMAkNDMQswCQYDVQQLDAJERDEPMA0GA1UEAwwGUm9v\n"
                    + "dENBMB4XDTI0MDUyNTE1MTgxNloXDTM0MDUyMzE1MTgxNlowRTELMAkGA1UEBhMC\n"
                    + "QUExCzAJBgNVBAgMAkJCMQswCQYDVQQKDAJDQzELMAkGA1UECwwCREQxDzANBgNV\n"
                    + "BAMMBlJvb3RDQTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABBFlLFtB5CjNbQSI\n"
                    + "jrawsVwdkC5GrMhrTX7BD46VF4WaFMcphqrhXDD/+SzQeyhWBEW0B2W0gqlywb8L\n"
                    + "HPYjOHGjYzBhMB0GA1UdDgQWBBRDCduCOe47k6HAWhuNjdmffQlYijAfBgNVHSME\n"
                    + "GDAWgBRDCduCOe47k6HAWhuNjdmffQlYijAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud\n"
                    + "DwEB/wQEAwIBhjAKBggqgRzPVQGDdQNIADBFAiASwfVZemJ53ykcWE4zy3LgSuAX\n"
                    + "zbP2Wr5dHpTxoedY+gIhAOrCge2+GkoQsn202H6Yp5kahjLYDLXuJnqWOOX3NSkn\n"
                    + "-----END CERTIFICATE-----";

    String secondRootTemCert =
            "-----BEGIN CERTIFICATE-----\n" + "MIIB4TCCAYagAwIBAgIBATAKBggqgRzPVQGDdTBFMQswCQYDVQQGEwJBQTELMAkG\n"
                    + "A1UECAwCQkIxCzAJBgNVBAoMAkNDMQswCQYDVQQLDAJERDEPMA0GA1UEAwwGUm9v\n"
                    + "dENBMB4XDTI0MDUyNTE1MTgxNloXDTM0MDUyMzE1MTgxNlowRjELMAkGA1UEBhMC\n"
                    + "QUExCzAJBgNVBAgMAkJCMQswCQYDVQQKDAJDQzELMAkGA1UECwwCREQxEDAOBgNV\n"
                    + "BAMMB2NsaWVudDEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATbh5txSIR7aiY4\n"
                    + "DMCBGTooo31lW/rdmVrSAEfuHK8O/b3ny/ZxVm+/RSf46R9IeMlwcdaiyWJ7MJvm\n"
                    + "iK83kXX/o2YwZDAdBgNVHQ4EFgQUoFYrNTMOyJWBidwRhRTJapqn/CswHwYDVR0j\n"
                    + "BBgwFoAUQwnbgjnuO5OhwFobjY3Zn30JWIowEgYDVR0TAQH/BAgwBgEB/wIBADAO\n"
                    + "BgNVHQ8BAf8EBAMCAYYwCgYIKoEcz1UBg3UDSQAwRgIhAI4zLBUNIMoTV0jBNltp\n"
                    + "WtLbrBh5mqKcLTZ3UezfxxAqAiEA2CCZ4+tFqUC3D3E0FWN15kuPzk92kYdPOJEP\n" + "HzWxhBg=\n"
                    + "-----END CERTIFICATE-----";

    String userTemCert =
            "-----BEGIN CERTIFICATE-----\n" + "MIIB1DCCAXugAwIBAgIBBTAKBggqgRzPVQGDdTBGMQswCQYDVQQGEwJBQTELMAkG\n"
                    + "A1UECAwCQkIxCzAJBgNVBAoMAkNDMQswCQYDVQQLDAJERDEQMA4GA1UEAwwHY2xp\n"
                    + "ZW50MTAeFw0yNDA1MjUxNTE4MTdaFw0zNDA1MjMxNTE4MTdaMEYxCzAJBgNVBAYT\n"
                    + "AkFBMQswCQYDVQQIDAJCQjELMAkGA1UECgwCQ0MxCzAJBgNVBAsMAkREMRAwDgYD\n"
                    + "VQQDDAdjbGllbnQxMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEKiYS5ot//QN2\n"
                    + "RhwzoO2bHpdfVr7EsAWBKFg8+uvA/V2KBLTNWgaesoSmPYF0sf5O/ulf4KzWwKVN\n"
                    + "UhWew32acaNaMFgwCQYDVR0TBAIwADALBgNVHQ8EBAMCAzgwHQYDVR0OBBYEFNFC\n"
                    + "emUjK4sOS0zo38mnEzc5JgOaMB8GA1UdIwQYMBaAFKBWKzUzDsiVgYncEYUUyWqa\n"
                    + "p/wrMAoGCCqBHM9VAYN1A0cAMEQCIFi0jpKEzkWsmXKmdDZ4rAAxdsJFQru2rCAv\n"
                    + "nZkwVW2jAiAmlJxI+iPda11RtPn4eYp+rBIBwt+GKS86PLdnvIIKyg==\n" + "-----END CERTIFICATE-----";

    @Test
    public void testCommonCertificateValidation() throws Exception {
        // 加载根证书和普通证书
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate caCert = CertUtil.certAnalyze(rootTemCert);
        X509Certificate rootCert = CertUtil.certAnalyze(secondRootTemCert);
        X509Certificate userCert = CertUtil.certAnalyze(userTemCert);

        testCertificateValidation(cf, caCert, userCert, rootCert);
    }

    @Test
    public void testEncCertificateValidation() throws Exception {
        // 加载根证书和普通证书
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = buildCaCert();
        X509Certificate userCert = buildEncCert();

        String rootCertStr = CertUtil.genCert(rootCert);
        String userCertStr = CertUtil.genCert(userCert);
        System.out.println(rootCertStr);
        System.out.println(userCertStr);

        testCertificateValidation(cf, rootCert, userCert);
    }

    @Test
    public void testSignCertificateValidation() throws Exception {
        // 加载根证书和普通证书
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = buildCaCert();
        X509Certificate userCert = buildSignCert();

        String rootCertStr = CertUtil.genCert(rootCert);
        String userCertStr = CertUtil.genCert(userCert);
        System.out.println(rootCertStr);
        System.out.println(userCertStr);

        testCertificateValidation(cf, rootCert, userCert);
    }

    void testCertificateValidation(CertificateFactory cf, X509Certificate rootCert, X509Certificate... userCerts)
            throws Exception {
        // 构建验证链
        List<X509Certificate> certs = new ArrayList<>();
        Collections.addAll(certs, userCerts);
        certs.add(rootCert); // 注意顺序，验证链应从待验证的证书开始到信任的根证书结束

        // 验证证书链
        CertPath cp = cf.generateCertPath(certs);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters params = new PKIXParameters(
                new HashSet<TrustAnchor>(Collections.singleton(new TrustAnchor(rootCert, null))));
        params.setRevocationEnabled(false); // 禁用CRL和OCSP检查以简化示例，实际应用中应启用
        CertPathValidatorResult result = cpv.validate(cp, params);

        // 验证结果
        assertNotNull("Certificate validation failed.", result);
    }


    @Test
    public void encrypt() throws Exception {
        byte[] mess = (rootTemCert + secondRootTemCert + userTemCert).getBytes(StandardCharsets.UTF_8);

        // SM2 cipher requires SM2 key
        KeyPair kp = PrivateKeyUtils.sm2GenerateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        Cipher cipher = Cipher.getInstance("SM2", BouncyCastleProvider.PROVIDER_NAME);
        // encrypt with public key
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(mess);
        byte[] ciphertext = cipher.doFinal();

        // decrypt with private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(ciphertext);
        byte[] decrypted = cipher.doFinal();

        // decrypted text should be identical to input
        assertEquals(Base64.getEncoder().encodeToString(mess), Base64.getEncoder().encodeToString(decrypted));
        assertEquals(new String(decrypted, StandardCharsets.UTF_8), new String(mess, StandardCharsets.UTF_8));
        System.out.println(new String(decrypted, StandardCharsets.UTF_8));
    }


    String sm2Pri =
            "-----BEGIN PRIVATE KEY-----\n" + "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgCtOzi3nJ6Rq+I2iz\n"
                    + "3fLkuva1mK5Rygkw7NBmJw8Um9mhRANCAASyjh8GcmQorZu2zT42IzTEtKopZFB/\n"
                    + "9pOaJd2d0LKOKKpEPu7eUFMGMK2NhXG3+G3ZCIgHhEbcAnhf3O5cVtN4\n" + "-----END PRIVATE KEY-----\n";

    String sm2Pub =
            "-----BEGIN PUBLIC KEY-----\n" + "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEso4fBnJkKK2bts0+NiM0xLSqKWRQ\n"
                    + "f/aTmiXdndCyjiiqRD7u3lBTBjCtjYVxt/ht2QiIB4RG3AJ4X9zuXFbTeA==\n" + "-----END PUBLIC KEY-----";

    @Test
    public void encryptWithSm2C1C2C3() throws Exception {
        byte[] mess = (rootTemCert + secondRootTemCert + userTemCert).getBytes(StandardCharsets.UTF_8);

        PrivateKey privateKey = PrivateKeyUtils.readPrivateKey(sm2Pri.getBytes());
        PublicKey publicKey = PrivateKeyUtils.buildPublicKey(sm2Pub);

        Cipher cipher = Cipher.getInstance("SM2", BouncyCastleProvider.PROVIDER_NAME);
        // encrypt with public key
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(mess);
        byte[] ciphertext = cipher.doFinal();

        System.out.println(Base64.getEncoder().encodeToString(ciphertext));

        // decrypt with private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(ciphertext);
        byte[] decrypted = cipher.doFinal();

        // decrypted text should be identical to input
        assertEquals(Base64.getEncoder().encodeToString(mess), Base64.getEncoder().encodeToString(decrypted));
        assertEquals(new String(decrypted, StandardCharsets.UTF_8), new String(mess, StandardCharsets.UTF_8));
        System.out.println(new String(decrypted, StandardCharsets.UTF_8));
    }


    @Test
    public void encryptWithSm2TongSuo() throws Exception {

        PrivateKey privateKey = PrivateKeyUtils.readPrivateKey(sm2Pri.getBytes());

        Cipher cipher = Cipher.getInstance("SM2", BouncyCastleProvider.PROVIDER_NAME);

        // 由tongsuo提供的sm2加密，是Asn1格式的并且是C1C3C2
        String data = "MHICIFe4gt5actsWQJyW88Lc4Nm7AuvugfAt5h+ufZhbVQdvAiEAgcU9k6W/tgD1LpfNbTLPSwbMXl2kj/6mHSmVro8vbj4EIDPfNoolusfC3e/jvVf2ROJsxsbMbaIQzxuieLp1acidBAl507sGlZj6W/E=";

        byte[] ciphertext = Base64.getDecoder().decode(data);

        byte[] asn1ToC1C3C2 = SM2Utils.changeAsn1ToC1C2C3(ciphertext);
        // decrypt with private key ，默认是C1C2C3
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(asn1ToC1C3C2);
        byte[] decrypted = cipher.doFinal();
        String decryptedStr = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println(decryptedStr);
        assertEquals("Helloword", decryptedStr);
    }

    @Test
    void encryptWithSm2C1C3C2() throws Exception {
        String data = (rootTemCert + secondRootTemCert + userTemCert);

        PrivateKey privateKey = PrivateKeyUtils.readPrivateKey(sm2Pri.getBytes());
        PublicKey publicKey = PrivateKeyUtils.buildPublicKey(sm2Pub);

        byte[] encrypt = SM2Utils.changeC1C3C2ToAsn1(SM2EncryptUtils.encrypt(publicKey, data));
        String encryptBase64 = Base64.getEncoder().encodeToString(encrypt);
        System.out.println(encryptBase64);

        byte[] cipherDataByte = SM2Utils.changeAsn1ToC1C3C2(Base64.getDecoder().decode(encryptBase64));
        String decrypt = SM2EncryptUtils.decrypt(privateKey, cipherDataByte);
        System.out.println(decrypt);
        assertEquals(data, decrypt);
    }

}
