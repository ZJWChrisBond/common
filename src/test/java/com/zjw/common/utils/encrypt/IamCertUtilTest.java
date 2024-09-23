package com.zjw.common.utils.encrypt;

import static com.zjw.common.utils.endecrypt.CertUtil.certAnalyze;
import static com.zjw.common.utils.endecrypt.CertUtil.csrAnalyze;
import static com.zjw.common.utils.endecrypt.CertUtil.csrBuilder;
import static com.zjw.common.utils.endecrypt.CertUtil.csrGetPublicKeyByPKCS;
import static com.zjw.common.utils.endecrypt.CertUtil.csrGetPublicKeyByX509;
import static com.zjw.common.utils.endecrypt.CertUtil.genCert;
import static com.zjw.common.utils.endecrypt.CertUtil.genPfx;
import static com.zjw.common.utils.endecrypt.CertUtil.genX509Certificate;
import static com.zjw.common.utils.endecrypt.CertUtil.getPrivateKey;
import static com.zjw.common.utils.endecrypt.CertUtil.getPublicKey;
import static com.zjw.common.utils.endecrypt.CertUtil.getX500Name;
import static com.zjw.common.utils.endecrypt.CertUtil.jksAnalyze;
import static com.zjw.common.utils.endecrypt.CertUtil.wrapKeyPem;

import com.zjw.common.utils.endecrypt.CertGeneratorUtils;
import com.zjw.common.utils.endecrypt.CertUtil;
import com.zjw.common.utils.endecrypt.RSAUtils;
import com.zjw.common.utils.endecrypt.RSAUtils2;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;


public class IamCertUtilTest {

    /**
     * CA
     */
    public static String publicRootMudulus = "00F8FE59C1C5A1A51423E937E16F09A3FB9FCBCB2573C6D71343469B9AB5EF8A8662E60D3FCE5DCFCF697C64BCFDC559A3B13BDF195EF20AB9F8A00B37D3D1BFBE214553222007317523E7CB335DF344D23B8FE2A0541A035980680273C0DE0384BA2BDC05B5227F2D46AEDFA09C551C328AB9C348B43DB42483F3B989B5E5981E7CB23FE43B6253EA64F89879BDC8DC7427A6CBA32C11E598DD058376D723B6C5763B6B71C0FD469FC0B3BE3B4FFF50AF4BFB08930FC7BACA804D6D5A1410E44DB59E160D57098D3374F7D221372710F2B0005F040430CB49D4B86B457826A84AD6C3585F327FC70B10F006E595DE9569DACE74A051E6F50824BF8EF4879BFCA5";
    public static String publicRootexpoent = "10001";
    public static String privateRootexpoent = "009EF06D871D8AA37F89B4D370D99A43CCD9221398E2A0A8A5A92A2725C8C111A1DAFB92B58A1BA40D77FE69A7A22E199C3E0443D3442228EAB164280508F738F83AF0AFB276D360A4AFB8C4A31373B818A2E0A3FF47F01AF744DA1FC697F4A0365748ABF810B9E68896380693D57716BAC486F3BB3322B81D1F05B307CECEB21C719171142791F39121896E63DBE0B106BF6E06606764EA304B7A95B9A2F9280D9A93D75392239C0DA29217472EEC87B9DE0EDE6BD8CE368A3582053AE666AAEAA9C2E76A3AAE2E494D76E1ED9FE56CE93D8302DAE64246DDECD2B82A803D9D8B1F882052DE2317DF89CC2A6F6DB28590839659FD6581ADD6EE3EFE1BE118A5C1";

    /**
     * USER
     **/
    public static String publicUserMudulus = "00B2C22D4997146374438623265AF1FA92AFE7AE4A4435D79F33D5155D823DD3B201E1BFEB0D1661B587397384473CE90DB90F816E65A1563E322D0BB590685A3345017AAA7F8FB6023CDA787A380CDD07213CEBDDE4C12B15D656ACDD3043B4D6A147500FB7056201EB179EB268F003ADEC6C7272671FF7A8B2411B1E6B7862D11177FBB4078FC47FBDF57C1720E973B3FF9648E0F8D1A213AF64C5742109D6ED0F75AF430688A78A6196E906F681E537DCA33CBC2B0CC358ECB79EF84F1599F68395FDCBA776A32195EF599A777C6EB807D58A59CE59576D2FC2A39447D58B7FED38B14417457B80E29E927990CF1B3524062DB0E763B71BAA38E83F442FF9B5";
    public static String publicUserexpoent = "10001";
    public static String privateUserexpoent = "0083A18EFDA89D9FDAA63A6939BE307FA67297B4F505236CC2D3C52DF56C89A0906CE8528D8056A1DEAD53B5E78B19A437B1B56446E9D9930B3BA18604CDF0B9B3153650A0AA4C25E7A1EDF257755CAB89AB8513DE92AB57D1BDC2978A4D171E5C09E8DC60A611F5A899F80BA92EB2C6D2D4CCCABDC98875B32887DEB358CA0E60D0223A0F946BF4F3B032E933D3A4BFFF7F792CBE0B11BEBC2DAA06BDF530CD11CA07B73F07540A812E6A26B43E41E1D7AF6F20511BA355AD68D49E3F4EE8BA282866900B2407B0C92325A091D75ADE455F987618E7DFA50A1010C51B7141354CB4B3C79C77C60906FE05229BCE77D51824862E8EC74C26E98C672047CFD2D761";


    public static String rootKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLNswq4ke3dj3t8EHsidIbdbLFDCp0aUmOk3tlRS3UJbQHZG8bboiYcoWW/5hCZ02K2azFaR8huNCgqgAMgSeb3HTpZXGrJawfFQm3daUvnDhm70Q3pu/+bO7xxuDfDXCpMkiG46GqjoKo2hpYdYpiMG7HM2sQMTNet4lWc4zedIzeu0IRvmIZwSo3ho16V+k/sB+CNbveLKLX6EKsUaPEU0kER83gwyXlFAi45hxdQbIjcOr2L7cxzBqHwhMJHpmZy/5bTrhcn9YLfI1IDhMYZEq5asdP8vb2Yz/z/Qd4zjzcHeGVweAc4hqYzo632jOTcZZLnjVJaH4G/O6yBkDjAgMBAAECggEAPq+2Nopb9iem/fWt2GJBapAZp/hTRlrOQomTOI+pDfbdfKRKM+uafnBhbk2FMgK85Fa2maUOYfAph045uqHCzq0ocXEGKfXyjRoHx8ymOrQVoAcyA3rfMJx47yNa7eOu+7qTreydS8gvXRf+pYgIurZXDeL6JWIQBylV19HIRDyhlRPVullMGoYLnutVBxqfi7LPp790wQ4xLy7fYRwkA2GxjSocl8fDv6DF6smKi1CNw+GA9OflhvfswI2lhBVIZa5zrSo7aHBSjuXCstUP57orPHRquBJV11KbsKEnPLRXCBXVgtiNUgmzeZMJGtq8M+K/mj8UBft9nJQgTB3H3QKBgQD4h77V1+4e3uhKdeqEpXy0dJe0h3FTksW/A/lAVf8VHs2OFpSTnIVTFVwZRe1v3TAm17yjjctLEeq20WTHebGzJuaPEMkGOmJVHUPkeLgHZwgBXsgya1SmIlrt+iy0uqShpF7i5HxcqrC0A8qqYzPPiOsd/HZlzBI2Jle1StdJ1QKBgQDRUmC1kTGXJ9nUCYXZh6lDAn28XQlTSV7FHZL7BKv0tZ7ka54/isNcJ6MMGsMRRg1Wyiv4kC/3kGQgBEL+TqNZ2/GEV3vhkr9WLYAQfiT8i1bRDgDi9Cr1JYz7samTjBEoVZaEQjrEUSyTcx3N5/DXeys/FEVHsQ7+X+x8hRLD1wKBgDq0Fad9MYmpLUUpRRO/4wzc3ViPBX2wFXVhAubnaTEb7YG6Y63aMsPFL9PoaIUbwdvq6WvYekRpHv+/xgY4AHlInvz8Af+umrtwBjFZMl7NP17TfIYsQ/pZ8xBzH0wxKeHkaWU+gwGAb+yVWLGWbQ6AUMjscSrqYQLZW64+10thAoGAGKq3gM4CZQiqL8WLg23sMVxayta/4ZO02k+44WHUjbrVZZ+U/3Hvwa1eFnAU6rUxnzel5N3A+VCHrAo0htlngJBdrrXMgHGVoKct/0OOQkB9U5dt3VDeuxLYwVRXYm7QGsuzOBTB7h6OvTWEnp4lkI8QMpfF7kPcO3e8W5Qm+PMCgYEA4b9VzjogskAkkRANR2O0e+WxF0LoXFKb/MTi81GoTbCBWnK8OjDZL/Kqc0rrLh9M+mcQ27V1jMCMMmhfe13BCE805khoAC9oLZhATb/VB2LBTu9pDcx27nwyQTTXhVbDUDn0x/NGbrYrn9SS/TL2ayY3SEN5G4jXoTgJigqm9x4=";
    public static String userKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDDXTS+apSZD1bHnf/re7KNaJr5bcb8MfuRPv91m3pU/rGTejV94u7i0IzCIrqqQ9L5rmYzpax0m8dI3e8H9kECGSbNBoDTYEjWSCC1TkfX+WJ+Gd6fKRPlO7pom4gmMvEBxbRDOfLDgHE7FPNqoZmG5MnxnLSw3eC+FQnhQvSRas/CJBgP/y7DF21AwTHcaVib6kuWrxqhBfl4ULZDZi/Qu2pUXRV3qse8G+EmMqP5Oksut4dVbZt+/FpM7HXYFRh8eV82mHy1o1djmrjQ+b0HUZuVDpQOLa9PhzgqZdW1ivSJ+8kJ1dktkMFBSt+JTDr49g3O31hc7qQgYtcd7jiNAgMBAAECggEAVTPDGwCUiiRcbnaD9IlgF7f1Tq8Hx1ltI61b8Ei8k3D4tR7pUVu1X4oguVI4IqWtz2K2A/RPQBPoV+kipFBLjcS2XVhmuskVOw795NSdFJ4YzHIv2y4pFSJ1a8XZHP++iE1XDrKpI4ZS27eJaYnM0T3arNrxGunJaFz4kBuJWhl9/aIkFCVl3/zchd9W827JJAeth7tSwXPSoX68b/1LKsAjKPUAjA7a4ytikjuUN2dSsuLRkVQK153y7G1EIhsCrvvdDFkF4rdo1fshmxWGAgBnsrNhaBXKxfsusp9yBKtePvLjG3NmTyX7W8VjXXX8tBrKRDw/I3ZKThRRLbqc6QKBgQDWGDoyW6vpeLElZfWPXYfnrjS2N4edX8W3ICefCpLsrDVSWFAB5/p3fHZllY3+DSmngV/nhdK/SgDeCTUN9NVXHQEJCHzAoLh1B0j70eecvTr2DYo5pnzB6hZK2c8FHoAvJWNtDWb7xxs3I7PiFFCxOLUlgUTriNxIoUrKQ1/r5wKBgQDpmm9xrUo9/MrOUuNPEO5DECGoptqVMrfUhgrV69YCtTdiFRevgW9eeLvgcEpOlex4qk0kEGatUBQFmlyZEMZLrp/V2MlLlouEdtTU/5SGlDpsG2sFzhK+m8pqh/CuMf+MkaMbWgILEw1Hdk7cU9lAG7lILynvS0pSJHJbsKiJawKBgCDjz+z0kFBpri0koLjJkZtR898aYMcYc3NSiUOxiCi7u+VOk9v3G09H25h3hTzGIOQOyAD1Wg7w+3kgyPm/5xZe6k3M8/1Ts4Km/9tPv9kgaPJr2hRJM1lG8O3G0DrlGKQlhkS2jl+XkuLBpVzR6iOPpqSAW2ojuFOgE7FG8HF5AoGAa8n24l0zhKbAbbORb0pApnErFsbm1TEx4b54AX1woo87nuZcp37yBIVxK36kyt4i3wq1zY5D0nTAyFURpQ84cHODDQma2GX+uoCadC36Op7q1jdQir0rqQf5vm47gCVR5WrN+DDwAGwqFG9itAd8lzgzpjsc/m2fPYfTvLsnCUECgYAlmMZVGi9/1dKS9SfjM7av2IS+p6rp8kWM4oQ5FrvqCdUXQoUeZ/EuzYDjJLTRATIBA3JM1GhITz3f417RPvxkiZN6YGG9CrQoQqA9kY2vhxksEUE81ZcsB4g20OewHlHNNZToCN2+tq2zNDYUN5nWzQBVaOwbGjPfL/wvN2NhbA==";


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 签发网关的RSA CA证书
     */
    @Test
    public void genGatewayCertsTest() throws Exception {
        //根证书Issue基本信息
        X500Name issuerName = getX500Name("zta-gateway-root", "bingo", "gz", "gd", "CN", "bingo");
        // 证书序列号
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        //证书有 起始日期 与 结束日期
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date notBefore = sdf.parse("2023-11-01 10:00:00");
        Date notAfter = sdf.parse("2133-11-01 10:00:00");

        KeyPair keyPair = RSAUtils.generateKeyPair();
        PublicKey rootPublicKey = keyPair.getPublic();
        PrivateKey rootPrivateKey = keyPair.getPrivate();

        //构建证书的build
        String cert = CertGeneratorUtils.buildRSACertStr(
                CertificationSigningRequestUtils.build(issuerName, issuerName, serial, notBefore, notAfter,
                        rootPublicKey, rootPrivateKey, null));

        System.out.println("root cert:\n");
        System.out.println("\n" + cert);

        X500Name reqName = getX500Name("zta-gateway", "bingo", "gz", "gd", "CN", "bingo");
        keyPair = RSAUtils.generateKeyPair();
        PublicKey userPublicKey = keyPair.getPublic();
        PrivateKey userPrivateKey = keyPair.getPrivate();

        GeneralName generalName = new GeneralName(GeneralName.dNSName, "zt-gateway");
        GeneralNames subjectAltNames = new GeneralNames(generalName);
        Extension subjectAlternativeNameEx = Extension.create(Extension.subjectAlternativeName, false, subjectAltNames);
        cert = CertGeneratorUtils.buildRSACertStr(
                CertificationSigningRequestUtils.build(issuerName, reqName, serial, notBefore, notAfter, userPublicKey,
                        rootPrivateKey,
                        Collections.singletonList(subjectAlternativeNameEx)));

        System.out.println("Private:\n");
        System.out.println(wrapKeyPem(userPrivateKey) + "\n");

        System.out.println("gateway cert:\n");
        System.out.println("\n" + cert);
    }

    /**
     * 产生公私钥 这就是产生公私钥的方法，其中核心参数是三个值： 公钥 模 公钥 指数 私钥 指数
     */
    @Test
    public void genRsaKeyPair() throws NoSuchAlgorithmException {
        Pair<RSAPublicKey, RSAPrivateKey> map = CertUtil.genKey();
        RSAPublicKey rsaPublicKey = map.getLeft();
        RSAPrivateKey rsaPrivateKey = map.getRight();

        String pkStr = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());

        System.out.println(pkStr);
        KeyPair keyPair = RSAUtils2.decodeKeyPair(pkStr);

        //公钥 模
        String publicMudulus = rsaPublicKey.getModulus().toString(16);
        //公钥 指数
        String publicExpoent = rsaPublicKey.getPublicExponent().toString(16);
        //私钥 指数
        String privateExpoent = rsaPrivateKey.getPrivateExponent().toString(16);
        //公钥 模
        String publicMuduluss = rsaPrivateKey.getModulus().toString(16);

        System.out.println(publicMudulus);
        System.out.println(publicExpoent);
        System.out.println(privateExpoent);
        System.out.println(publicMuduluss);

        System.out.println(publicMudulus.equals(publicMuduluss));
    }

    /**
     * 生成 证书请求文件
     *
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    @Test
    public String genUserCsrTest()
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        X500Name reqName = getX500Name("TicPay", "Laser", "BeiJing", "BeiJing", "CN", "R&D");
        //构建 用户证书 对应的公钥
        PublicKey userPublicKey = getPublicKey(16, publicUserMudulus, publicUserexpoent);
        //构建CAroot证书 对应的私钥
        PrivateKey userPrivateKey = getPrivateKey(16, publicUserMudulus, privateRootexpoent);
        String s = csrBuilder(reqName, userPublicKey, userPrivateKey);
        System.out.println("\n" + s);
        return s;
    }

    /**
     * 签发CA证书
     */
    @Test
    public String genCaCertTest() throws Exception {
        //根证书Issue基本信息
        X500Name issuerName = getX500Name("iam", "bingo", "gz", "gd", "CN", "bingo");
        // 证书序列号
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        //证书有 起始日期 与 结束日期
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date notBefore = sdf.parse("2023-11-01 10:00:00");
        Date notAfter = sdf.parse("2033-11-01 10:00:00");

        /*//构建 用户证书 对应的公钥
        PublicKey userPublicKey = getPublicKey(16, publicRootMudulus, publicRootexpoent);
        //构建CA Root证书 对应的私钥
        PrivateKey rootPrivateKey = getPrivateKey(16, publicRootMudulus, publicRootexpoent);*/

        KeyPair keyPair = RSAUtils2.decodeKeyPair(rootKey);
        PublicKey userPublicKey = keyPair.getPublic();
        PrivateKey rootPrivateKey = keyPair.getPrivate();

        String privateStr = Base64.getEncoder().encodeToString(rootPrivateKey.getEncoded());
        System.out.println(privateStr);
        //构建证书的build
        String cert = CertGeneratorUtils.buildRSACertStr(
                CertificationSigningRequestUtils.build(issuerName, issuerName, serial, notBefore, notAfter,
                        userPublicKey, rootPrivateKey, null));
        System.out.println("\n" + cert);

        return cert;
    }

    /**
     * 生成 根PFX证书
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SecurityException
     * @throws SignatureException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void genRootPfxTest() throws NoSuchAlgorithmException,
            InvalidKeyException, SecurityException, SignatureException,
            KeyStoreException, CertificateException, IOException, OperatorCreationException, InvalidKeySpecException {

        String certPath = "./target/pfxGenRoot.pfx";
        PrivateKey rootPrivateKey = getPrivateKey(16, publicRootMudulus, privateRootexpoent);
        PublicKey rootPublicKey = getPublicKey(16, publicRootMudulus, publicRootexpoent);

        String passWord = "12345678";

        X500Name issuer = getX500Name("huangpeng", "Laser", "BeiJing", "BeiJing", "CN", "R&D");

        X509Certificate x509Certificate = genX509Certificate(
                new BigInteger("11121", 10), (new Date(System.currentTimeMillis() - 500000)),
                (new Date(System.currentTimeMillis() + 500000)),
                issuer, issuer, rootPrivateKey, rootPublicKey);

        genPfx(x509Certificate, rootPrivateKey, passWord, certPath);

    }

    /**
     * 生成用户证书 签发证书的颁发者信息 要与生成ca证书时的签发信息一致，不然会出错。证书链验证不过。
     */
    @Test
    public void genUserCertTest() throws Exception {
        //根证书Issue基本信息
        X500Name issuerName = getX500Name("iam", "bingo", "gz", "gd", "CN", "bingo");
        // 用户证书 基本使用者
        X500Name reqName = getX500Name("kid-1", "bingo", "gz", "gd", "CN", "bingo");
        // 证书序列号
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        //证书 起始日期 与 结束日期
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date notBefore = sdf.parse("2018-08-02 00:00:00");
        Date notAfter = sdf.parse("2028-07-01 00:00:00");

        /*//构建 用户证书 对应的公钥
        PublicKey userPublicKey = getPublicKey(16, publicUserMudulus, publicUserexpoent);
        //构建CAroot证书 对应的私钥
        PrivateKey rootPrivateKey = getPrivateKey(16, publicRootMudulus, privateRootexpoent);*/

        KeyPair rootPK = RSAUtils2.decodeKeyPair(rootKey);
        KeyPair userPk = RSAUtils2.decodeKeyPair(userKey);

        PublicKey userPublicKey = userPk.getPublic();
        PrivateKey rootPrivateKey = rootPK.getPrivate();
        //构建证书的build
        String cert = CertGeneratorUtils.buildRSACertStr(
                CertificationSigningRequestUtils.build(issuerName, reqName, serial, notBefore, notAfter, userPublicKey,
                        rootPrivateKey, null));

        System.out.println("\n" + cert);
    }

    /**
     * 生成 用户PFX证书
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SecurityException
     * @throws SignatureException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void genUserPfxTest() throws NoSuchAlgorithmException,
            SecurityException, KeyStoreException, CertificateException, IOException, OperatorCreationException, InvalidKeySpecException {

        String certPath = "./target/pfxGenUser.pfx";
        PrivateKey rootPrivateKey = getPrivateKey(16, publicRootMudulus, privateRootexpoent);
        PrivateKey userPrivateKey = getPrivateKey(16, publicUserMudulus, privateUserexpoent);
        PublicKey userPublicKey = getPublicKey(16, publicUserMudulus, publicUserexpoent);

        String passWord = "12345678";

        X500Name issuer = getX500Name("huangpeng", "Laser", "BeiJing", "BeiJing", "CN", "R&D");
        X500Name reqSubject = getX500Name("huang1", "Laser", "BeiJing", "BeiJing", "CN", "R&D");

        X509Certificate x509Certificate = genX509Certificate(
                new BigInteger("111", 10), (new Date(System.currentTimeMillis() - 500000)),
                (new Date(System.currentTimeMillis() + 500000)),
                issuer, reqSubject, rootPrivateKey, userPublicKey);

        genPfx(x509Certificate, userPrivateKey, passWord, certPath);

    }

    /**
     * pfx 解析
     */
    @Test
    public void pfxAnalyzeTest() {
        final String KEYSTORE_FILE = "./target/pfxGenUser.pfx";
        final String password = "12345678";
        try {
            FileInputStream fis = new FileInputStream(KEYSTORE_FILE);
            HashMap<Object, Object> objectObjectHashMap = CertUtil.pfxAnalze(fis, password);
            System.out.println(objectObjectHashMap.get(PrivateKey.class));
            System.out.println(objectObjectHashMap.get(PublicKey.class));
            System.out.println(objectObjectHashMap.get(Certificate.class));
            //pfx ==> cert
            System.out.println(CertUtil.genCert((Certificate) objectObjectHashMap.get(Certificate.class)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * csr解析
     *
     * @throws IOException
     */
    @Test
    public void csrAnalyzeTest()
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, OperatorCreationException {

        String crsRequest = genUserCsrTest();

        PKCS10CertificationRequest pkcs10CertificationRequest = csrAnalyze(crsRequest);

        System.out.println(csrGetPublicKeyByX509(pkcs10CertificationRequest));
        System.out.println(csrGetPublicKeyByPKCS(pkcs10CertificationRequest));
    }

    /**
     * cer解析
     *
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     */
    @Test
    public void certAnalyzeTest()
            throws Exception {
        String cert = genCaCertTest();
        certAnalyze(cert);
    }

    /**
     * jks文件解析
     *
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    @Test
    public void jksAnalyzeTest()
            throws Exception {
        final String keystoreFile = "./target/device.jks";
        final String password = "12345678";

        createKeyStore(keystoreFile, password);

        FileInputStream fis = new FileInputStream(keystoreFile);
        Map<Class<?>, Object> hashmap = jksAnalyze(fis, password);
        System.out.println(hashmap.get(Certificate.class));
        System.out.println(hashmap.get(PrivateKey.class));

        //jks ==> cert
        System.out.println(genCert((Certificate) hashmap.get(Certificate.class)));

        //jks ==> pfx
        genPfx((Certificate) hashmap.get(Certificate.class), (PrivateKey) hashmap.get(PrivateKey.class), password,
                keystoreFile);
    }

    protected void createKeyStore(String filename, String password)
            throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");

        ks.load(null, password.toCharArray());
        ks.store(new FileOutputStream(filename), password.toCharArray());

        ks.load(new FileInputStream(filename), password.toCharArray());
        String caCert = genCaCertTest();
        X509Certificate certificate = certAnalyze(caCert);

        Certificate[] chain = new Certificate[]{certificate};
        KeyPair keyPair = RSAUtils2.decodeKeyPair(rootKey);

        String entryKey = certificate.getSubjectX500Principal().getName();
        ks.setCertificateEntry(entryKey, certificate);
        ks.setKeyEntry(entryKey, keyPair.getPrivate(), password.toCharArray(), chain);

        ks.store(new FileOutputStream(filename), password.toCharArray());
    }

}
