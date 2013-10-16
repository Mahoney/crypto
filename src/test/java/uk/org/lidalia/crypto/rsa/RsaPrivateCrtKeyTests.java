package uk.org.lidalia.crypto.rsa;

import org.junit.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RsaPrivateCrtKeyTests {

    @Test
    public void equalsRSAPrivateCrtKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RsaKeyUtils.RSA_ALGORITHM_NAME);
        keyPairGenerator.initialize(1024);

        RSAPrivateCrtKey javaPrivateKey = (RSAPrivateCrtKey) keyPairGenerator.generateKeyPair().getPrivate();
        RsaPrivateCrtKey publicKey = new RsaPrivateCrtKey(javaPrivateKey);

        assertTrue(javaPrivateKey.equals(publicKey));
        assertTrue(publicKey.equals(javaPrivateKey));

        RSAPrivateCrtKey javaPrivateKey2 = (RSAPrivateCrtKey) keyPairGenerator.generateKeyPair().getPrivate();
        RsaPrivateCrtKey publicKey2 = new RsaPrivateCrtKey(javaPrivateKey2);

        assertFalse(javaPrivateKey.equals(javaPrivateKey2));
        assertFalse(javaPrivateKey.equals(publicKey2));
        assertFalse(publicKey.equals(javaPrivateKey2));
        assertFalse(publicKey.equals(publicKey2));
    }
}
