package uk.org.lidalia.crypto.rsa;

import org.junit.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RsaPrivateCrtKeyTests {

    @Test
    public void equalSymmetric() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RsaKeyUtils.RSA_ALGORITHM_NAME);
        keyPairGenerator.initialize(1024);

        RSAPrivateCrtKey javaPrivateKey = (RSAPrivateCrtKey) keyPairGenerator.generateKeyPair().getPrivate();
        RsaPrivateCrtKey privateKey = new RsaPrivateCrtKey(javaPrivateKey);

        assertTrue(javaPrivateKey.equals(privateKey));
        assertTrue(privateKey.equals(javaPrivateKey));
    }

    @Test
    public void notEqualSymmetric() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RsaKeyUtils.RSA_ALGORITHM_NAME);
        keyPairGenerator.initialize(1024);

        RSAPrivateCrtKey javaPrivateKey = (RSAPrivateCrtKey) keyPairGenerator.generateKeyPair().getPrivate();
        RsaPrivateCrtKey privateKey = RsaKeyPair.generate().getPrivateKey();

        assertFalse(javaPrivateKey.equals(privateKey));
        assertFalse(privateKey.equals(javaPrivateKey));
    }

    @Test
    public void equalReflective() {
        RsaPrivateCrtKey privateKey = RsaKeyPair.generate().getPrivateKey();

        assertTrue(privateKey.equals(privateKey));
    }

    @Test
    public void equal() throws InvalidKeySpecException {
        RsaPrivateCrtKey privateKey = RsaKeyPair.generate().getPrivateKey();
        RsaPrivateCrtKey privateKey2 = RsaPrivateCrtKey.fromEncoded(privateKey.getEncoded());

        assertTrue(privateKey.equals(privateKey2));
        assertTrue(privateKey2.equals(privateKey));
    }

    @Test
    public void notEqual() throws InvalidKeySpecException {
        RsaPrivateCrtKey privateKey = RsaKeyPair.generate().getPrivateKey();
        RsaPrivateCrtKey privateKey2 = RsaKeyPair.generate().getPrivateKey();

        assertFalse(privateKey.equals(privateKey2));
        assertFalse(privateKey2.equals(privateKey));
    }
}
