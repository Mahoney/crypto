package uk.org.lidalia.crypto.rsa;

import org.junit.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public class RsaPrivateCrtKeyTests {

    @Test
    public void equalSymmetric() throws NoSuchAlgorithmException {
        final RSAPrivateCrtKey javaPrivateKey
                = getJavaPrivateKey();
        final RsaPrivateCrtKey privateKey
                = RsaPrivateCrtKey.from(javaPrivateKey);

        assertTrue(javaPrivateKey.equals(privateKey));
        assertTrue(privateKey.equals(javaPrivateKey));
    }

    @Test
    public void notEqualSymmetric() throws NoSuchAlgorithmException {
        final RSAPrivateCrtKey javaPrivateKey
                = getJavaPrivateKey();
        final RsaPrivateCrtKey privateKey
                = RsaPrivateCrtKey.generate();

        assertFalse(javaPrivateKey.equals(privateKey));
        assertFalse(privateKey.equals(javaPrivateKey));
    }

    @Test
    public void equalReflective() {
        final RsaPrivateCrtKey privateKey
                = RsaPrivateCrtKey.generate();

        assertTrue(privateKey.equals(privateKey));
    }

    @Test
    public void equal() throws InvalidKeySpecException {
        final RsaPrivateCrtKey privateKey
                = RsaPrivateCrtKey.generate();
        final RsaPrivateCrtKey privateKey2
                = RsaPrivateCrtKey.fromEncoded(privateKey.getEncoded());

        assertTrue(privateKey.equals(privateKey2));
        assertTrue(privateKey2.equals(privateKey));
    }

    @Test
    public void notEqual() throws InvalidKeySpecException {
        final RsaPrivateCrtKey privateKey
                = RsaPrivateCrtKey.generate();
        final RsaPrivateCrtKey privateKey2
                = RsaPrivateCrtKey.generate();

        assertFalse(privateKey.equals(privateKey2));
        assertFalse(privateKey2.equals(privateKey));
    }

    private RSAPrivateCrtKey getJavaPrivateKey()
            throws NoSuchAlgorithmException {

        final KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance(RSA.name());
        keyPairGenerator.initialize(1024);

        return (RSAPrivateCrtKey) keyPairGenerator
                .generateKeyPair()
                .getPrivate();
    }
}
