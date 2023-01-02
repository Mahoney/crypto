package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Immutable, typed wrapper around a {@link javax.crypto.Cipher}
 *
 * @param <E> The type of {@link EncryptKey} this cipher can use to encrypt
 * @param <D> The type of {@link DecryptKey} this cipher can use to decrypt
 */
public final class Cipher<E extends EncryptKey<E, D>, D extends DecryptKey<E, D>> {

    private final String transformation;
    private final ThreadLocal<javax.crypto.Cipher> threadLocalCipher;

    public Cipher(String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.transformation = transformation;
        Thread constructionThread = Thread.currentThread();
        javax.crypto.Cipher initial = javax.crypto.Cipher.getInstance(transformation);
        this.threadLocalCipher = ThreadLocal.withInitial(() -> {
            if (Thread.currentThread() == constructionThread) {
                return initial;
            } else {
                try {
                    return javax.crypto.Cipher.getInstance(toString());
                } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new AssertionError("Should be impossible - checked construction of " + this + " on construction", e);
                }
            }
        });
    }

    EncryptedBytes<E, D> encrypt(final Bytes decrypted, E key) throws EncryptionFailedException {
        try {
            return EncryptedBytes.of(doCrypto(decrypted, key, javax.crypto.Cipher.ENCRYPT_MODE), this);
        } catch (final Exception e) {
            throw new EncryptionFailedException(e);
        }
    }

    Bytes decrypt(final Bytes encrypted, D key) throws DecryptionFailedException {
        try {
            return Bytes.of(doCrypto(encrypted, key, javax.crypto.Cipher.DECRYPT_MODE));
        } catch (final Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    private byte[] doCrypto(
        final Bytes input,
        final Key key,
        final int encryptMode
    ) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        final javax.crypto.Cipher cipher = threadLocalCipher.get();
        cipher.init(encryptMode, key);
        return cipher.doFinal(input.array());
    }

    @Override
    public String toString() {
        return transformation;
    }
}
