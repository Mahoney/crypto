package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class CipherAlgorithm {

    private final String cipherPaddingName;

    public CipherAlgorithm(String cipherPaddingName) {
        this.cipherPaddingName = cipherPaddingName;
    }

    public Bytes encrypt(final Bytes decrypted, Key key) {
        try {
            return doCrypto(decrypted, key, Cipher.ENCRYPT_MODE);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException(
                    "Encrypting with an RSA key should always work. " +
                            "Using key="+this, e);
        }
    }

    public Bytes decrypt(final Bytes encrypted, Key key) throws DecryptionFailedException {
        try {
            return doCrypto(encrypted, key, Cipher.DECRYPT_MODE);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    private Bytes doCrypto(
            final Bytes input,
            final Key key,
            final int encryptMode) throws Exception {

        final Cipher cipher = cipher();
        try {
            cipher.init(encryptMode, key);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(
                    "An RSA Key should never be invalid for doing crypto. " +
                            "Using key="+this, e);
        }
        return Bytes.of(cipher.doFinal(input.array()));
    }

    private Cipher cipher() {
        try {
            return Cipher.getInstance(toString());
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RequiredAlgorithmNotPresent(toString(), e);
        }
    }

    @Override
    public String toString() {
        return cipherPaddingName;
    }
}
