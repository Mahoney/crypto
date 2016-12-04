package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.BaseAsymmetricKeyAlgorithm;

import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static uk.org.lidalia.crypto.CipherAlgorithm.EcbOaepWithSha1AndMgf1;

public class Rsa extends BaseAsymmetricKeyAlgorithm<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey> {

    public static final Rsa RSA = new Rsa();

    private Rsa() {
        super("RSA", EcbOaepWithSha1AndMgf1);
    }

    @Override
    public RsaPrivateCrtKey generateKeyPair(int keySize) {
        return RsaPrivateCrtKey.from(generateDecoratedKeyPair(keySize));
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
