package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.HashAlgorithm;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

class RsaKeyUtils {

    static final String RSA_ALGORITHM_NAME = "RSA";
    static final String ECB_MODE = "ECB";
    static final String PKCS1_PADDING = "PKCS1Padding";
    private static final String CIPHER_ALGORITHM = RSA_ALGORITHM_NAME + "/" + ECB_MODE + "/" + PKCS1_PADDING;
    private static final KeyFactory RSA_KEY_FACTORY = getRsaKeyFactory();

    private static KeyFactory getRsaKeyFactory() {
        try {
            return KeyFactory.getInstance(RSA_ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw requiredAlgorithmNotPresentException(e, RSA_ALGORITHM_NAME);
        }
    }

    static KeyFactory rsaKeyFactory() {
        return RSA_KEY_FACTORY;
    }

    static Signature signatureFor(HashAlgorithm hashAlgorithm) {
        String algorithm = hashAlgorithm + "with" + RSA_ALGORITHM_NAME;
        try {
            return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw requiredAlgorithmNotPresentException(e, algorithm);
        }
    }

    static IllegalStateException requiredAlgorithmNotPresentException(GeneralSecurityException e, final String algorithm) {
        return new IllegalStateException(algorithm + " is a required algorithm!", e);
    }

    static Cipher cipher() {
        try {
            return Cipher.getInstance(CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw requiredAlgorithmNotPresentException(e, CIPHER_ALGORITHM);
        }
    }
}
