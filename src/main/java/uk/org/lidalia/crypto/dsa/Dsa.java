package uk.org.lidalia.crypto.dsa;

import uk.org.lidalia.crypto.BaseAsymmetricCryptoAlgorithm;

import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Dsa extends BaseAsymmetricCryptoAlgorithm<Dsa> {

    public static final Dsa DSA = new Dsa();

    private Dsa() {
        super("DSA");
    }

    @Override
    public int defaultKeySize() {
        return 2048;
    }

    @Override
    public DsaKeyPair generateKeyPair() {
        return generateKeyPair(defaultKeySize());
    }

    @Override
    public DsaKeyPair generateKeyPair(int keySize) {
        return DsaKeyPair.from(generateDecoratedKeyPair(keySize));
    }

    @Override
    public DsaPublicKey publicKey(KeySpec keySpec) throws InvalidKeySpecException {
        return DsaPublicKey.from((DSAPublicKey) keyFactory().generatePublic(keySpec));
    }

    @Override
    public DsaPrivateKey privateKey(KeySpec keySpec) throws InvalidKeySpecException {
        return DsaPrivateKey.from((DSAPrivateKey) keyFactory().generatePrivate(keySpec));
    }
}
