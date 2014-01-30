package org.nick.hce.pki;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import android.util.Base64;

public class Crypto {

    public static final String PBKDF2_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";

    private static String DELIMITER = "]";

    // SHA-1 output length
    private static int KEY_LENGTH = 160;
    private static int ITERATION_COUNT = 5000;
    private static final int PKCS5_SALT_LENGTH = 8;

    private static SecureRandom random = new SecureRandom();

    private Crypto() {
    }

    public static String protectPassword(String password) {
        byte[] salt = generateSalt();
        byte[] keyBytes = pbkdf2(password, salt);

        return String.format("%s%s%s", toBase64(salt), DELIMITER,
                toBase64(keyBytes));
    }

    private static byte[] pbkdf2(String password, byte[] salt) {
        try {
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                    ITERATION_COUNT, KEY_LENGTH);
            SecretKeyFactory keyFactory = SecretKeyFactory
                    .getInstance(PBKDF2_DERIVATION_ALGORITHM);

            return keyFactory.generateSecret(keySpec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean checkPassword(String protectedPassword,
            String password) {
        String[] fields = protectedPassword.split(DELIMITER);
        if (fields.length != 2) {
            throw new IllegalArgumentException(
                    "Invalid protected password format");
        }

        byte[] salt = fromBase64(fields[0]);
        byte[] keyBytes = fromBase64(fields[1]);

        byte[] derivedKeyBytes = pbkdf2(password, salt);

        return Arrays.equals(keyBytes, derivedKeyBytes);
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[PKCS5_SALT_LENGTH];
        random.nextBytes(salt);

        return salt;
    }

    public static byte[] sign(PrivateKey privateKey, byte[] signedData) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(privateKey);
            sig.update(signedData);

            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static String toHex(byte[] bytes) {
        StringBuffer buff = new StringBuffer();
        for (byte b : bytes) {
            buff.append(String.format("%02X", b));
        }

        return buff.toString();
    }

    public static String toBase64(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.decode(base64, Base64.NO_WRAP);
    }

}
