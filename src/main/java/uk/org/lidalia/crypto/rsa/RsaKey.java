package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.CipherPadding;
import uk.org.lidalia.crypto.DecryptionFailedException;
import uk.org.lidalia.crypto.HashAlgorithm;
import uk.org.lidalia.crypto.RequiredAlgorithmNotPresent;
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

public abstract class RsaKey<T extends Key & RSAKey> implements RSAKey, uk.org.lidalia.crypto.Key<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey> {

    final T decorated;

    RsaKey(final T decorated) {
        this.decorated = decorated;
    }

    public Bytes encrypt(final Bytes decrypted, CipherPadding cipherPadding) {
        try {
            return doCrypto(decrypted, cipherPadding, Cipher.ENCRYPT_MODE);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException(
                    "Encrypting with an RSA key should always work. " +
                    "Using key="+this, e);
        }
    }

    public Bytes decrypt(final Bytes encrypted, CipherPadding cipherPadding) throws DecryptionFailedException {
        try {
            return doCrypto(encrypted, cipherPadding, Cipher.DECRYPT_MODE);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    public Bytes encrypt(Bytes decrypted) {
        return encrypt(decrypted, algorithm().defaultCipherPadding());
    }

    public Bytes encrypt(byte[] decrypted, CipherPadding cipherPadding) {
        return encrypt(Bytes.of(decrypted), cipherPadding);
    }

    public Bytes encrypt(byte[] decrypted) {
        return encrypt(decrypted, algorithm().defaultCipherPadding());
    }

    public Bytes encrypt(String input, Charset charset, CipherPadding cipherPadding) {
        return encrypt(input.getBytes(charset), cipherPadding);
    }

    public Bytes encrypt(String input, Charset charset) {
        return encrypt(input, charset, algorithm().defaultCipherPadding());
    }

    public Bytes encrypt(String input, CipherPadding cipherPadding) {
        return encrypt(input, UTF_8, cipherPadding);
    }

    public Bytes encrypt(String input) {
        return encrypt(input, UTF_8);
    }

    public Bytes decrypt(Bytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherPadding());
    }

    public Bytes decrypt(byte[] encrypted, CipherPadding cipherPadding) throws DecryptionFailedException {
        return decrypt(Bytes.of(encrypted), cipherPadding);
    }

    public Bytes decrypt(byte[] encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherPadding());
    }

    public Bytes decrypt(Encoded<?> encrypted, CipherPadding cipherPadding) throws DecryptionFailedException {
        return decrypt(encrypted.decode(), cipherPadding);
    }

    public Bytes decrypt(Encoded<?> encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherPadding());
    }

    private Bytes doCrypto(
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

    @Override
    public Rsa algorithm() {
        return RSA;
    }

    protected Signature signatureFor(HashAlgorithm hashAlgorithm) {
        final String algorithm = hashAlgorithm + "with" + algorithm();
        try {
            return Signature.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(algorithm, e);
        }
    }

    private Cipher cipher(CipherPadding cipherPadding) {
        String algorithmWithPadding = algorithm() +""+ cipherPadding;
        try {
            return Cipher.getInstance(algorithmWithPadding);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RequiredAlgorithmNotPresent(algorithmWithPadding, e);
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
