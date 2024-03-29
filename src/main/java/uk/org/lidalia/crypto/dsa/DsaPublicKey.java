package uk.org.lidalia.crypto.dsa;

import uk.org.lidalia.crypto.PublicKey;
import uk.org.lidalia.lang.Bytes;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import static uk.org.lidalia.crypto.dsa.Dsa.DSA;

public final class DsaPublicKey
        extends DsaKey<DSAPublicKey>
        implements DSAPublicKey, PublicKey<Dsa> {

    public static DsaPublicKey fromEncoded(final Bytes publicKeyEncoded)
            throws InvalidKeySpecException {
        final X509EncodedKeySpec publicKeySpec
                = new X509EncodedKeySpec(publicKeyEncoded.array());
        return fromKeySpec(publicKeySpec);
    }

    public static DsaPublicKey fromKeySpec(final KeySpec publicKeySpec)
            throws InvalidKeySpecException {
        return DSA.publicKey(publicKeySpec);
    }

    public static DsaPublicKey from(final DSAPublicKey decorated) {
        return new DsaPublicKey(decorated);
    }

    private DsaPublicKey(final DSAPublicKey decorated) {
        super(decorated);
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getY() {
        return decorated.getY();
    }
}
