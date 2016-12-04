package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.BaseAsymmetricKeyAlgorithm;
import uk.org.lidalia.crypto.CipherAlgorithm;
import uk.org.lidalia.crypto.RequiredAlgorithmNotPresent;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Rsa extends BaseAsymmetricKeyAlgorithm<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey> {

    public static final CipherAlgorithm<RsaPublicKey, RsaPrivateCrtKey> RsaEcbPkcs1Padding;
    public static final CipherAlgorithm<RsaPublicKey, RsaPrivateCrtKey> RsaEcbOaepWithSha1AndMgf1Padding;
    public static final CipherAlgorithm<RsaPublicKey, RsaPrivateCrtKey> RsaEcbOaepWithSha256AndMgf1Padding;

    static {
        try {
            RsaEcbPkcs1Padding = new CipherAlgorithm<>("RSA/ECB/PKCS1Padding");
            RsaEcbOaepWithSha1AndMgf1Padding = new CipherAlgorithm<>("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            RsaEcbOaepWithSha256AndMgf1Padding = new CipherAlgorithm<>("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent("", e);
        }
    }

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
