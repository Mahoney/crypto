package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface EncryptKey<E extends EncryptKey<E, D>, D extends DecryptKey<E, D>> extends CryptoKey<E, D> {

    default EncryptionResult encrypt(Bytes decrypted, CipherAlgorithm<E, D> cipherAlgorithm) throws EncryptionFailedException {
        return cipherAlgorithm.encrypt(decrypted, this);
    }

    default EncryptionResult encrypt(Bytes decrypted) throws EncryptionFailedException {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptionResult encrypt(byte[] decrypted, CipherAlgorithm<E, D> cipherAlgorithm) throws EncryptionFailedException {
        return encrypt(Bytes.of(decrypted), cipherAlgorithm);
    }

    default EncryptionResult encrypt(byte[] decrypted) throws EncryptionFailedException {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptionResult encrypt(String input, Charset charset, CipherAlgorithm<E, D> cipherAlgorithm) throws EncryptionFailedException {
        return encrypt(input.getBytes(charset), cipherAlgorithm);
    }

    default EncryptionResult encrypt(String input, Charset charset) throws EncryptionFailedException {
        return encrypt(input, charset, algorithm().defaultCipherAlgorithm());
    }

    default EncryptionResult encrypt(String input, CipherAlgorithm<E, D> cipherAlgorithm) throws EncryptionFailedException {
        return encrypt(input, UTF_8, cipherAlgorithm);
    }

    default EncryptionResult encrypt(String input) throws EncryptionFailedException {
        return encrypt(input, UTF_8);
    }

}
