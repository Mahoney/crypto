package uk.org.lidalia.crypto.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;

import static uk.org.lidalia.crypto.rsa.RsaKeyUtils.RSA_ALGORITHM_NAME;
import static uk.org.lidalia.crypto.rsa.RsaKeyUtils.requiredAlgorithmNotPresentException;

public class RsaKeyPair {

    public static RsaKeyPair generate() throws IllegalStateException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME);
            keyPairGenerator.initialize(1024);
            return from(keyPairGenerator.generateKeyPair());
        } catch (NoSuchAlgorithmException e) {
            throw requiredAlgorithmNotPresentException(e, RSA_ALGORITHM_NAME);
        }
    }

    public static RsaKeyPair from(KeyPair keyPair) {
        RsaPrivateCrtKey privateKey = new RsaPrivateCrtKey((RSAPrivateCrtKey) keyPair.getPrivate());
        return new RsaKeyPair(privateKey);
    }

    private final RsaPrivateCrtKey privateCrtKey;

    public RsaKeyPair(RsaPrivateCrtKey privateCrtKey) {
        this.privateCrtKey = privateCrtKey;
    }

    public KeyPair toKeyPair() {
        return new KeyPair(getPublicKey(), getPrivateKey());
    }

    public RsaPrivateCrtKey getPrivateKey() {
        return privateCrtKey;
    }

    public RsaPublicKey getPublicKey() {
        return privateCrtKey.getPublicKey();
    }
}
