package uk.org.lidalia.crypto.core;

import uk.org.lidalia.lang.Bytes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public final class CipherAlgorithm<E extends EncryptKey<E, D>, D extends DecryptKey<E, D>> {

    private final String cipherPaddingName;
    private final ThreadLocal<Cipher> threadLocalCipher;

    public CipherAlgorithm(String cipherPaddingName) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipherPaddingName = cipherPaddingName;
        Thread constructionThread = Thread.currentThread();
        Cipher initial = Cipher.getInstance(cipherPaddingName);
        this.threadLocalCipher = ThreadLocal.withInitial(() -> {
            if (Thread.currentThread() == constructionThread) {
                return initial;
            } else {
                try {
                    return Cipher.getInstance(toString());
                } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new AssertionError("Should be impossible - checked construction of " + toString() + " on construction", e);
                }
            }
        });
    }

    EncryptedBytes encrypt(final Bytes decrypted, EncryptKey key) {
        try {
            return EncryptedBytes.of(doCrypto(decrypted, key, Cipher.ENCRYPT_MODE));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new AssertionError("Should not be possible to get these on encryption", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e); // TODO better exception!
        }
    }

    Bytes decrypt(final EncryptedBytes encrypted, DecryptKey key) throws DecryptionFailedException {
        try {
            return Bytes.of(doCrypto(encrypted, key, Cipher.DECRYPT_MODE));
        } catch (final Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    private byte[] doCrypto(
        final Bytes input,
        final Key key,
        final int encryptMode
    ) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        final Cipher cipher = threadLocalCipher.get();
        cipher.init(encryptMode, key);
        return cipher.doFinal(input.array());
    }

    @Override
    public String toString() {
        return cipherPaddingName;
    }
}
