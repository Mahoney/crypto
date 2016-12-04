package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.AsymmetricKey;
import uk.org.lidalia.crypto.CipherAlgorithm;
import uk.org.lidalia.crypto.HashAlgorithm;
import uk.org.lidalia.crypto.RequiredAlgorithmNotPresent;
import uk.org.lidalia.encoding.Bytes;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAKey;

import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public abstract class RsaKey<T extends Key & RSAKey> implements RSAKey, AsymmetricKey<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey> {

    final T decorated;

    RsaKey(final T decorated) {
        this.decorated = decorated;
    }

    @Override
    public Rsa algorithm() {
        return RSA;
    }

    protected Bytes doCrypto(
            final Bytes input,
            final CipherAlgorithm cipherAlgorithm,
            final int encryptMode) throws Exception {

        final Cipher cipher = cipher(cipherAlgorithm);
        try {
            cipher.init(encryptMode, this);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(
                    "An RSA Key should never be invalid for doing crypto. " +
                    "Using key="+this, e);
        }
        return Bytes.of(cipher.doFinal(input.array()));
    }

    private Cipher cipher(CipherAlgorithm cipherAlgorithm) {
        String algorithmWithPadding = algorithm() +"/"+ cipherAlgorithm;
        try {
            return Cipher.getInstance(algorithmWithPadding);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RequiredAlgorithmNotPresent(algorithmWithPadding, e);
        }
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
