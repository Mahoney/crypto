package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class CipherAlgorithm<E extends EncryptKey<E, D>, D extends DecryptKey<E, D>> {

    private final String cipherPaddingName;

    public CipherAlgorithm(String cipherPaddingName) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher.getInstance(cipherPaddingName);
        this.cipherPaddingName = cipherPaddingName;
    }

    public Bytes encrypt(final Bytes decrypted, EncryptKey key) {
        try {
            return doCrypto(decrypted, key, Cipher.ENCRYPT_MODE);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new AssertionError("Should not be possible to get these on encryption", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e); // TODO better exception!
        }
    }

    public Bytes decrypt(final Bytes encrypted, DecryptKey key) throws DecryptionFailedException {
        try {
            return doCrypto(encrypted, key, Cipher.DECRYPT_MODE);
        } catch (final Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    private Bytes doCrypto(
        final Bytes input,
        final Key key,
        final int encryptMode
    ) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        final Cipher cipher = cipher();
        cipher.init(encryptMode, key);
        return Bytes.of(cipher.doFinal(input.array()));
    }

    private Cipher cipher() {
        try {
            return Cipher.getInstance(toString());
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new AssertionError("Should be impossible - checked construction of "+toString()+" on construction", e);
        }
    }

    @Override
    public String toString() {
        return cipherPaddingName;
    }
}
