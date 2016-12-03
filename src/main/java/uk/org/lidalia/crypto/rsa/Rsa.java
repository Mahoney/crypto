package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.BaseAlgorithm;
import uk.org.lidalia.crypto.RequiredAlgorithmNotPresent;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Rsa extends BaseAlgorithm<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey> {

    public static final Rsa RSA = new Rsa();

    private Rsa() {
        super("RSA", "/ECB/PKCS1Padding");
    }

    @Override
    public RsaPrivateCrtKey generateKeyPair(int keySize) {
        try {
            final KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance(name());
            keyPairGenerator.initialize(keySize);
            return RsaPrivateCrtKey.from(keyPairGenerator.generateKeyPair());
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(name(), e);
        }
    }

    @Override
    public RsaPublicKey publicKey(KeySpec keySpec) throws InvalidKeySpecException {
        return RsaPublicKey.from((RSAPublicKey) keyFactory().generatePublic(keySpec));
    }

    @Override
    public RsaPrivateCrtKey privateKey(KeySpec keySpec) throws InvalidKeySpecException {
        return RsaPrivateCrtKey.from((RSAPrivateCrtKey) keyFactory().generatePrivate(keySpec));
    }
}
