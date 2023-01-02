package uk.org.lidalia.crypto.dsa;

import uk.org.lidalia.crypto.PrivateKey;
import uk.org.lidalia.lang.Bytes;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import static uk.org.lidalia.crypto.dsa.Dsa.DSA;

public final class DsaPrivateKey
        extends DsaKey<DSAPrivateKey>
        implements DSAPrivateKey, PrivateKey<Dsa> {

    public static DsaPrivateKey from(KeyPair keyPair) {
        return from((DSAPrivateKey) keyPair.getPrivate());
    }

    public static DsaPrivateKey fromEncoded(final Bytes privateKeyEncoded)
            throws InvalidKeySpecException {
        final KeySpec privateKeySpec
                = new PKCS8EncodedKeySpec(privateKeyEncoded.array());
        return fromKeySpec(privateKeySpec);
    }

    public static DsaPrivateKey fromKeySpec(final KeySpec privateKeySpec)
            throws InvalidKeySpecException {
        return DSA.privateKey(privateKeySpec);
    }

    public static DsaPrivateKey from(final DSAPrivateKey decorated) {
        return new DsaPrivateKey(decorated);
    }

    private DsaPrivateKey(final DSAPrivateKey decorated) {
        super(decorated);
    }

    @Override
    public BigInteger getX() {
        return decorated.getX();
    }
}
