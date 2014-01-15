package uk.org.lidalia.crypto.rsa;

import org.junit.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RsaPublicKeyTests {

    @Test
    public void equalSymmetric() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RsaKeyUtils.RSA_ALGORITHM_NAME);
        keyPairGenerator.initialize(1024);

        RSAPublicKey javaPublicKey = (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();
        RsaPublicKey publicKey = new RsaPublicKey(javaPublicKey);

        assertTrue(javaPublicKey.equals(publicKey));
        assertTrue(publicKey.equals(javaPublicKey));
    }

    @Test
    public void notEqualSymmetric() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RsaKeyUtils.RSA_ALGORITHM_NAME);
        keyPairGenerator.initialize(1024);

        RsaPublicKey publicKey = RsaKeyPair.generate().getPublicKey();
        RSAPublicKey javaPublicKey = (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();

        assertFalse(publicKey.equals(javaPublicKey));
        assertFalse(javaPublicKey.equals(publicKey));
    }

    @Test
    public void equalReflective() {
        RsaPublicKey publicKey = RsaKeyPair.generate().getPublicKey();

        assertTrue(publicKey.equals(publicKey));
    }

    @Test
    public void equal() throws InvalidKeySpecException {
        RsaPublicKey publicKey = RsaKeyPair.generate().getPublicKey();
        RsaPublicKey publicKey2 = RsaPublicKey.fromEncoded(publicKey.getEncoded());

        assertTrue(publicKey.equals(publicKey2));
        assertTrue(publicKey2.equals(publicKey));
    }

    @Test
    public void notEqual() throws InvalidKeySpecException {
        RsaPublicKey publicKey = RsaKeyPair.generate().getPublicKey();
        RsaPublicKey publicKey2 = RsaKeyPair.generate().getPublicKey();

        assertFalse(publicKey.equals(publicKey2));
        assertFalse(publicKey2.equals(publicKey));
    }
}
