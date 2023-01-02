package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.BaseAsymmetricKeyAlgorithm;
import uk.org.lidalia.crypto.Cipher;
import uk.org.lidalia.crypto.CryptoKeyAlgorithm;
import uk.org.lidalia.crypto.RequiredAlgorithmNotPresent;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Rsa extends BaseAsymmetricKeyAlgorithm<RsaPublicKey, RsaPrivateKey, RsaPrivateKey> implements CryptoKeyAlgorithm<RsaPublicKey, RsaPrivateKey> {

    public static final Cipher<RsaPublicKey, RsaPrivateKey> RsaEcbPkcs1Padding;
    public static final Cipher<RsaPublicKey, RsaPrivateKey> RsaEcbOaepWithSha1AndMgf1Padding;
    public static final Cipher<RsaPublicKey, RsaPrivateKey> RsaEcbOaepWithSha256AndMgf1Padding;
    public static final Cipher<RsaPublicKey, RsaPrivateKey> RsaEcbOaepWithSha384AndMgf1Padding;
    public static final Cipher<RsaPublicKey, RsaPrivateKey> RsaEcbOaepWithSha512AndMgf1Padding;

    static {
        try {
            RsaEcbPkcs1Padding                 = new Cipher<>("RSA/ECB/PKCS1Padding");
            RsaEcbOaepWithSha1AndMgf1Padding   = new Cipher<>("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            RsaEcbOaepWithSha256AndMgf1Padding = new Cipher<>("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            RsaEcbOaepWithSha384AndMgf1Padding = new Cipher<>("RSA/ECB/OAEPWithSHA-384AndMGF1Padding");
            RsaEcbOaepWithSha512AndMgf1Padding = new Cipher<>("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent("", e);
        }
    }

    public static final Rsa RSA = new Rsa();

    private Rsa() {
        super("RSA");
    }

    @Override
    public int defaultKeySize() {
        return 4096;
    }

    @Override
    public RsaPrivateKey generateKeyPair(int keySize) {
        return RsaPrivateKey.of(generateDecoratedKeyPair(keySize));
    }

    @Override
    public RsaPublicKey publicKey(KeySpec keySpec) throws InvalidKeySpecException {
        return RsaPublicKey.of((RSAPublicKey) keyFactory().generatePublic(keySpec));
    }

    @Override
    public RsaPrivateKey privateKey(KeySpec keySpec) throws InvalidKeySpecException {
        return RsaPrivateKey.of((RSAPrivateCrtKey) keyFactory().generatePrivate(keySpec));
    }

    @Override
    public Cipher<RsaPublicKey, RsaPrivateKey> defaultCipherAlgorithm() {
        return RsaEcbOaepWithSha256AndMgf1Padding;
    }
}
