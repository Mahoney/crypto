package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.AsymmetricKey;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAKey;

import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public abstract class RsaKey<T extends Key & RSAKey> implements RSAKey, AsymmetricKey<RsaPublicKey, RsaPrivateKey, RsaPrivateKey> {

    final T decorated;

    RsaKey(final T decorated) {
        this.decorated = requireNonNull(decorated);
    }

    @Override
    public Rsa algorithm() {
        return RSA;
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
    public final BigInteger getModulus() {
        return decorated.getModulus();
    }

    @Override
    public String toString() {
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
