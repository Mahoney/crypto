package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.*;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAKey;

import static java.nio.charset.StandardCharsets.UTF_8;
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
            final CipherPadding cipherPadding,
            final int encryptMode) throws Exception {

        final Cipher cipher = cipher(cipherPadding);
        try {
            cipher.init(encryptMode, this);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(
                    "An RSA Key should never be invalid for doing crypto. " +
                    "Using key="+this, e);
        }
        return Bytes.of(cipher.doFinal(input.array()));
    }

    private Cipher cipher(CipherPadding cipherPadding) {
        String algorithmWithPadding = algorithm() +""+ cipherPadding;
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
