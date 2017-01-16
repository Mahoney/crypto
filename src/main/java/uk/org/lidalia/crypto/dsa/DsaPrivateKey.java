package uk.org.lidalia.crypto.dsa;

import uk.org.lidalia.crypto.CipherAlgorithm;
import uk.org.lidalia.crypto.DecryptionFailedException;
import uk.org.lidalia.crypto.HashAlgorithm;
import uk.org.lidalia.crypto.PrivateKey;
import uk.org.lidalia.encoding.Bytes;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import static uk.org.lidalia.crypto.dsa.Dsa.DSA;

public final class DsaPrivateKey
        extends DsaKey<DSAPrivateKey>
        implements DSAPrivateKey,
                   PrivateKey<DsaPublicKey, DsaPrivateKey, DsaKeyPair> {

    public static DsaPrivateKey from(KeyPair keyPair) {
        return from((DSAPrivateKey) keyPair.getPrivate());
    }

    public static DsaPrivateKey fromEncoded(final byte[] privateKeyEncoded)
            throws InvalidKeySpecException {
        final KeySpec privateKeySpec
                = new PKCS8EncodedKeySpec(privateKeyEncoded);
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
