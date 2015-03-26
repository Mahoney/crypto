package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.DecryptionFailedException;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.interfaces.RSAKey;

import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public abstract class RsaKey<T extends Key & RSAKey> implements RSAKey, uk.org.lidalia.crypto.Key<RsaPublicKey, RsaPrivateCrtKey> {

    final T decorated;

    RsaKey(final T decorated) {
        this.decorated = decorated;
    }

    public byte[] encrypt(final byte[] input) {
        try {
            return doCrypto(input, Cipher.ENCRYPT_MODE);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException(
                    "Encrypting with an RSA key should always work. " +
                    "Using key="+this, e);
        }
    }

    public byte[] decrypt(final byte[] input) throws DecryptionFailedException {
        try {
            return doCrypto(input, Cipher.DECRYPT_MODE);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    private byte[] doCrypto(
            final byte[] input,
            final int encryptMode) throws Exception {

        final Cipher cipher = RSA.getCipher();
        try {
            cipher.init(encryptMode, this);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(
                    "An RSA Key should never be invalid for doing crypto. " +
                    "Using key="+this, e);
        }
        return cipher.doFinal(input);
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
