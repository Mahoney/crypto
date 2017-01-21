package uk.org.lidalia.crypto.dsa;

import uk.org.lidalia.crypto.AsymmetricKey;
import uk.org.lidalia.crypto.HashAlgorithm;
import uk.org.lidalia.crypto.RequiredAlgorithmNotPresent;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;

import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.crypto.dsa.Dsa.DSA;

public abstract class DsaKey<T extends Key & DSAKey> implements DSAKey, AsymmetricKey<DsaPublicKey, DsaPrivateKey, DsaKeyPair> {

    final T decorated;

    DsaKey(final T decorated) {
        this.decorated = requireNonNull(decorated);
    }

    @Override
    public Dsa algorithm() {
        return DSA;
    }

    protected Signature signatureFor(HashAlgorithm hashAlgorithm) {
        final String algorithm = hashAlgorithm + "with" + algorithm();
        try {
            return Signature.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(algorithm, e);
        }
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public final String getAlgorithm() {
        return decorated.getAlgorithm();
    }

    @Override
    public final String getFormat() {
        return decorated.getFormat();
    }

    @Override
    public final byte[] getEncoded() {
        return decorated.getEncoded();
    }

    @Override
    public final DSAParams getParams() {
        return decorated.getParams();
    }

    @Override
    public final String toString() {
        return decorated.toString();
    }

    @Override
    public final boolean equals(Object other) {
        return this == other || decorated.equals(other);
    }

    @Override
    public final int hashCode() {
        return decorated.hashCode();
    }
}