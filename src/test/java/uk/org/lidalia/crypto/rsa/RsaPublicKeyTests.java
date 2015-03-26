package uk.org.lidalia.crypto.rsa;

import org.junit.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public class RsaPublicKeyTests {

    @Test
    public void equalSymmetric() throws NoSuchAlgorithmException {
        final RSAPublicKey javaPublicKey = makeJavaPublicKey();
        final RsaPublicKey publicKey = RsaPublicKey.from(javaPublicKey);

        assertTrue(javaPublicKey.equals(publicKey));
        assertTrue(publicKey.equals(javaPublicKey));
    }

    @Test
    public void notEqualSymmetric() throws NoSuchAlgorithmException {
        final RSAPublicKey javaPublicKey = makeJavaPublicKey();
        final RsaPublicKey publicKey = RsaPrivateCrtKey.generate().publicKey();

        assertFalse(publicKey.equals(javaPublicKey));
        assertFalse(javaPublicKey.equals(publicKey));
    }

    @Test
    public void equalReflective() {
        final RsaPublicKey publicKey = RsaPrivateCrtKey.generate().publicKey();

        assertTrue(publicKey.equals(publicKey));
    }

    @Test
    public void equal() throws InvalidKeySpecException {
        final RsaPublicKey publicKey = RsaPrivateCrtKey.generate().publicKey();
        final RsaPublicKey publicKey2
                = RsaPublicKey.fromEncoded(publicKey.getEncoded());

        assertTrue(publicKey.equals(publicKey2));
        assertTrue(publicKey2.equals(publicKey));
    }

    @Test
    public void notEqual() throws InvalidKeySpecException {
        final RsaPublicKey publicKey = RsaPrivateCrtKey.generate().publicKey();
        final RsaPublicKey publicKey2 = RsaPrivateCrtKey.generate().publicKey();

        assertFalse(publicKey.equals(publicKey2));
        assertFalse(publicKey2.equals(publicKey));
    }

    private RSAPublicKey makeJavaPublicKey() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance(RSA.getName());
        keyPairGenerator.initialize(1024);

        return (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();
    }
}
