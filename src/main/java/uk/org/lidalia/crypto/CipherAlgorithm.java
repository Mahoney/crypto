package uk.org.lidalia.crypto;

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
                    throw new AssertionError("Should be impossible - checked construction of " + this + " on construction", e);
                }
            }
        });
    }

    EncryptedBytes encrypt(final Bytes decrypted, E key) throws EncryptionFailedException {
        try {
            return EncryptedBytes.of(doCrypto(decrypted, key, Cipher.ENCRYPT_MODE));
        } catch (final Exception e) {
            throw new EncryptionFailedException(e);
        }
    }

    Bytes decrypt(final EncryptedBytes encrypted, D key) throws DecryptionFailedException {
        try {
            return Bytes.of(doCrypto(encrypted.bytes(), key, Cipher.DECRYPT_MODE));
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
