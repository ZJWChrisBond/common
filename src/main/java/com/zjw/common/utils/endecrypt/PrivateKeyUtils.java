package com.zjw.common.utils.endecrypt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * rsa 和 sm2 私钥 工具
 *
 * @author zjw
 */
public class PrivateKeyUtils {

    private static final String EC_ALGORITHM = "EC";
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String KEY = "KEY--";

    /**
     * 获取SM2密钥对生成器
     */
    public static KeyPairGenerator sm2Generator() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // 获取SM2椭圆曲线的参数
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 使用SM2参数初始化生成器
        kpg.initialize(sm2Spec);
        return kpg;
    }

    public static KeyPair sm2GenerateKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return sm2Generator().generateKeyPair();
    }

    public static PrivateKey readPrivateKey(byte[] pemPrivateKeyBytes) throws IOException {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pemPrivateKeyBytes);
                InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream);
                PEMParser pemParser = new PEMParser(inputStreamReader)) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(PROVIDER);
            if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair) object;
                return converter.getPrivateKey((pemKeyPair).getPrivateKeyInfo());
            }
            if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                return converter.getPrivateKey(privateKeyInfo);
            }
            throw new IllegalArgumentException("Unsupported PEM format");
        }
    }

    public static PublicKey buildPublicKey(String pemPublicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        try (PemReader pemReader = new PemReader(new StringReader(pemPublicKey))) {
            PemObject pemObject = pemReader.readPemObject();

            // 检查pemObject是否为空，防止空指针异常
            if (pemObject == null || pemObject.getContent().length == 0) {
                throw new IllegalArgumentException("PEM content is empty.");
            }

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemObject.getContent());
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, PROVIDER);
            return keyFactory.generatePublic(keySpec);
        } catch (IOException | IllegalStateException e) {
            throw new InvalidKeyException("Failed to read PEM public key.", e);
        }
    }

    public static String extractPem(String pem) throws IllegalArgumentException {
        String privateKeyPem;

        if (pem.contains(PRIVATE_KEY_HEADER)) {
            privateKeyPem = extractKeyPem(pem, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
        } else {
            if (pem.contains(KEY)) {
                throw invalidPEM(PRIVATE_KEY_HEADER);
            }
            privateKeyPem = pem.trim().replace("\n", "");
        }

        return privateKeyPem;
    }

    public static String wrapPrivateKeyPem(String privateKeyPem) {
        return PRIVATE_KEY_HEADER + "\n" + privateKeyPem + "\n" + PRIVATE_KEY_FOOTER;
    }

    public static String rewrapPrivateKeyPem(String pem) throws IllegalArgumentException {
        return wrapPrivateKeyPem(extractPem(pem));
    }

    public static String extractKeyPem(String content, String header, String footer) {
        int start = content.indexOf(header);
        if (start < 0) {
            throw invalidPEM(header);
        }
        int end = content.indexOf(footer);
        if (end < 0) {
            throw invalidPEM(footer);
        }
        return content.substring(start + header.length(), end).trim().replace("\n", "");
    }

    private static IllegalArgumentException invalidPEM(String key) {
        return new IllegalArgumentException("Invalid pem, '" + key + "' not found");
    }

    private PrivateKeyUtils() {
    }
}
