package com.zjw.common.utils.endecrypt;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * AES对称加密
 *
 * @author zjw
 */
public class AESUtil {

    private static final String KEY_AES = "AES";
    private static final String KEY_MD5 = "MD5";
    private static final MessageDigest md5Digest;

    private static final String KEY_TYPE = "{aes}";

    static {
        try {
            md5Digest = MessageDigest.getInstance(KEY_MD5);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Not a valid encrypt/decrypt algorithm", e);
        }
    }

    /**
     * 加密
     */
    public static String encrypt(String data, String key) {
        return doAES(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     */
    public static String decrypt(String data, String key) {
        return doAES(data, key, Cipher.DECRYPT_MODE);
    }


    /**
     * 加解密
     */
    private static String doAES(String data, String key, int mode) {
        try {
            boolean encrypt = mode == Cipher.ENCRYPT_MODE;
            byte[] content;
            if (encrypt) {
                if (StringUtils.startsWith(data, KEY_TYPE)) {
                    return data;
                }
                content = data.getBytes(StandardCharsets.UTF_8);
            } else {
                if (!StringUtils.startsWith(data, KEY_TYPE)) {
                    return data;
                }
                data = StringUtils.removeStart(data, KEY_TYPE);
                content = Base64.getDecoder().decode(data.getBytes());
            }
            SecretKeySpec keySpec = new SecretKeySpec(md5Digest.digest(key.getBytes(StandardCharsets.UTF_8)), KEY_AES);
            Cipher cipher = Cipher.getInstance(KEY_AES);
            cipher.init(mode, keySpec);
            byte[] result = cipher.doFinal(content);
            if (encrypt) {
                return KEY_TYPE + new String(Base64.getEncoder().encode(result));
            } else {
                return new String(result, StandardCharsets.UTF_8);

            }
        } catch (Exception e) {
            throw new IllegalStateException("unable to encrypt/decrypt", e);
        }
    }

}
