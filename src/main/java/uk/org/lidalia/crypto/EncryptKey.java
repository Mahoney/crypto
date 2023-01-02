package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface EncryptKey<E extends EncryptKey<E, D>, D extends DecryptKey<E, D>> extends CipherKey<E, D> {

    default EncryptedBytes encrypt(Bytes decrypted, Cipher<E, D> cipher) throws EncryptionFailedException {
        //noinspection unchecked
        return cipher.encrypt(decrypted, (E) this);
    }

    default EncryptedBytes encrypt(Bytes decrypted) throws EncryptionFailedException {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes encrypt(byte[] decrypted, Cipher<E, D> cipher) throws EncryptionFailedException {
        return encrypt(Bytes.of(decrypted), cipher);
    }

    default EncryptedBytes encrypt(byte[] decrypted) throws EncryptionFailedException {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes encrypt(String input, Charset charset, Cipher<E, D> cipher) throws EncryptionFailedException {
        return encrypt(input.getBytes(charset), cipher);
    }

    default EncryptedBytes encrypt(String input, Charset charset) throws EncryptionFailedException {
        return encrypt(input, charset, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes encrypt(String input, Cipher<E, D> cipher) throws EncryptionFailedException {
        return encrypt(input, UTF_8, cipher);
    }

    default EncryptedBytes encrypt(String input) throws EncryptionFailedException {
        return encrypt(input, UTF_8);
    }

}
