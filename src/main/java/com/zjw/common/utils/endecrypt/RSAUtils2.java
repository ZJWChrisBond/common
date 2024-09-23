package com.zjw.common.utils.endecrypt;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtils2 {

    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    private static final String KEY = "KEY--";

    private RSAUtils2() {

    }

    /**
     * Decode the pem content to {@link KeyPair}.
     *
     * @throws IllegalArgumentException if the pem is invalid.
     */
    public static KeyPair decodeKeyPair(String pem) throws IllegalArgumentException {
        String privateKeyPem;

        if (pem.contains(PRIVATE_KEY_HEADER)) {
            privateKeyPem = extractKeyPem(pem, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
        } else {
            if (pem.contains(KEY)) {
                throw invalidPEM(PRIVATE_KEY_HEADER);
            }
            privateKeyPem = pem.trim().replace("\n", "");
        }

        PrivateKey privateKey = readPrivateKey(Base64.getMimeDecoder().decode(privateKeyPem));
        PublicKey publicKey = generatePublicKey(privateKey);

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Generates a new {@link KeyPair} with length 2048.
     */
    public static KeyPair generateKeyPair() {
        return generateKeyPair(2048);
    }

    /**
     * Generates a new {@link KeyPair} with given length.
     */
    public static KeyPair generateKeyPair(int length) {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(length);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * Generates the {@link PublicKey} from a {@link PrivateKey}
     *
     * @throws IllegalArgumentException if the private key is not a valid rsa private key.
     */
    public static PublicKey generatePublicKey(PrivateKey privateKey) throws IllegalArgumentException {
        if (!(privateKey instanceof RSAPrivateCrtKey)) {
            throw new IllegalArgumentException("Invalid RSA private key");
        }
        try {
            RSAPrivateCrtKey privateCrtKey = (RSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateCrtKey.getModulus(),
                    privateCrtKey.getPublicExponent());
            return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String extractKeyPem(String content, String header, String footer) {
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

    private static PrivateKey readPrivateKey(byte[] bytes) {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static PublicKey readPublicKey(byte[] bytes) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static IllegalArgumentException invalidPEM(String key) {
        return new IllegalArgumentException("Invalid pem, '" + key + "' not found");
    }
}
