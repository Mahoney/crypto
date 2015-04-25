package uk.org.lidalia.crypto.rsa;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class Rsa extends BaseAlgorithm<RsaPublicKey, RsaPrivateCrtKey> {

    public static final Rsa RSA = new Rsa();

    private Rsa() {
        super("RSA", "/ECB/PKCS1Padding");
    }

    @Override
    public RsaPrivateCrtKey generateKeyPair() {
        try {
            final KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance(name());
            keyPairGenerator.initialize(1024);
            return RsaPrivateCrtKey.from(keyPairGenerator.generateKeyPair());
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(name(), e);
        }
    }
}
