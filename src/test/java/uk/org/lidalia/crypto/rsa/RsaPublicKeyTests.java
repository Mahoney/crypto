package uk.org.lidalia.crypto.rsa;

import org.junit.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RsaPublicKeyTests {

    @Test
    public void equalsRSAPublicKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RsaKeyUtils.RSA_ALGORITHM_NAME);
        keyPairGenerator.initialize(1024);

        RSAPublicKey javaPublicKey = (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();
        RsaPublicKey publicKey = new RsaPublicKey(javaPublicKey);

        assertTrue(javaPublicKey.equals(publicKey));
        assertTrue(publicKey.equals(javaPublicKey));

        RSAPublicKey javaPublicKey2 = (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();
        RsaPublicKey publicKey2 = new RsaPublicKey(javaPublicKey2);

        assertFalse(javaPublicKey.equals(javaPublicKey2));
        assertFalse(javaPublicKey.equals(publicKey2));
        assertFalse(publicKey.equals(javaPublicKey2));
        assertFalse(publicKey.equals(publicKey2));
    }
}
