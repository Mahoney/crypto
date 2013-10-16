package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.HashAlgorithm;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

class RsaKeyUtils {

    static final String RSA_ALGORITHM_NAME = "RSA";

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

    static IllegalStateException requiredAlgorithmNotPresentException(NoSuchAlgorithmException e, final String algorithm) {
        return new IllegalStateException(algorithm + " is a required algorithm!", e);
    }
}
