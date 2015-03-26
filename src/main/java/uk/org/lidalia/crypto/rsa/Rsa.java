package uk.org.lidalia.crypto.rsa;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

class Rsa extends Algorithm<RsaPublicKey, RsaPrivateCrtKey> {

    static Rsa RSA = new Rsa();

    Rsa() {
        super("RSA", "/ECB/PKCS1Padding");
    }

    @Override
    RsaPrivateCrtKey generate() {
        try {
            final KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance(getName());
            keyPairGenerator.initialize(1024);
            return RsaPrivateCrtKey.from(keyPairGenerator.generateKeyPair());
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(getName(), e);
        }
    }
}
