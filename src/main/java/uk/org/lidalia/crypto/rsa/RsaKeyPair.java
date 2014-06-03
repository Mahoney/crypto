package uk.org.lidalia.crypto.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import static uk.org.lidalia.crypto.rsa.RsaKeyUtils.RSA_ALGORITHM_NAME;
import static uk.org.lidalia.crypto.rsa.RsaKeyUtils.requiredAlgorithmNotPresentException;

public final class RsaKeyPair {

    public static RsaKeyPair generate() throws IllegalStateException {
        try {
            final KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME);
            keyPairGenerator.initialize(1024);
            return from(keyPairGenerator.generateKeyPair());
        } catch (final NoSuchAlgorithmException e) {
            throw requiredAlgorithmNotPresentException(e, RSA_ALGORITHM_NAME);
        }
    }

    public static RsaKeyPair from(KeyPair keyPair) {
        final PrivateKey basePrivateKey = keyPair.getPrivate();
        final RsaPrivateCrtKey privateKey
                = RsaPrivateCrtKey.from((RSAPrivateCrtKey) basePrivateKey);
        return from(privateKey);
    }

    public static RsaKeyPair from(final RsaPrivateCrtKey privateCrtKey) {
        return new RsaKeyPair(privateCrtKey);
    }

    private final RsaPrivateCrtKey privateCrtKey;
    private final RsaPublicKey publicKey;
    private final KeyPair keyPair;

    private RsaKeyPair(final RsaPrivateCrtKey privateCrtKey) {
        this.privateCrtKey = privateCrtKey;
        this.publicKey = privateCrtKey.getPublicKey();
        this.keyPair = new KeyPair(publicKey, privateCrtKey);
    }

    public KeyPair toKeyPair() {
        return keyPair;
    }

    public RsaPrivateCrtKey getPrivateKey() {
        return privateCrtKey;
    }

    public RsaPublicKey getPublicKey() {
        return publicKey;
    }
}
