package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.EncryptKey;
import uk.org.lidalia.crypto.PublicKey;
import uk.org.lidalia.encoding.Bytes;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public final class RsaPublicKey
        extends RsaKey<RSAPublicKey>
        implements RSAPublicKey, PublicKey<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey>,
        EncryptKey<RsaPublicKey, RsaPrivateCrtKey> {

    public static RsaPublicKey fromEncoded(final Bytes publicKeyEncoded)
            throws InvalidKeySpecException {
        final X509EncodedKeySpec publicKeySpec
                = new X509EncodedKeySpec(publicKeyEncoded.array());
        return fromKeySpec(publicKeySpec);
    }

    public static RsaPublicKey fromKeySpec(final KeySpec publicKeySpec)
            throws InvalidKeySpecException {
        return RSA.publicKey(publicKeySpec);
    }

    public static RsaPublicKey from(final RSAPublicKey decorated) {
        return new RsaPublicKey(decorated);
    }

    private RsaPublicKey(final RSAPublicKey decorated) {
        super(decorated);
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getPublicExponent() {
        return decorated.getPublicExponent();
    }
}
