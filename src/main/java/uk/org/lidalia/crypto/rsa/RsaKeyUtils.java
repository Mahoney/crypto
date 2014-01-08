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

    static KeyFactory rsaKeyFactory() {
        try {
            return KeyFactory.getInstance(RSA_ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw requiredAlgorithmNotPresentException(e, RSA_ALGORITHM_NAME);
        }
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
        String algorithm = RSA_ALGORITHM_NAME+"/"+ECB_MODE+"/"+ PKCS1_PADDING;
        try {
            return Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw requiredAlgorithmNotPresentException(e, algorithm);
        }
    }
}
