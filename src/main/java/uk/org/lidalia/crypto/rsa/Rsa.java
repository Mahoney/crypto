package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.BaseAsymmetricKeyAlgorithm;
import uk.org.lidalia.crypto.CipherAlgorithm;

import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Rsa extends BaseAsymmetricKeyAlgorithm<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey> {

    public static final CipherAlgorithm RsaEcbPkcs1Padding = new CipherAlgorithm("RSA/ECB/PKCS1Padding");
    public static final CipherAlgorithm RsaEcbOaepWithSha1AndMgf1Padding = new CipherAlgorithm("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");

    public static final Rsa RSA = new Rsa();

    private Rsa() {
        super("RSA", RsaEcbPkcs1Padding);
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
