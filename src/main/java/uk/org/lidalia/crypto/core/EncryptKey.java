package uk.org.lidalia.crypto.core;

import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface EncryptKey<E extends EncryptKey<E, D>, D extends DecryptKey<E, D>> extends CryptoKey<E, D> {

    default EncryptedBytes encrypt(Bytes decrypted, CipherAlgorithm<E, D> cipherAlgorithm) {
        return cipherAlgorithm.encrypt(decrypted, this);
    }

    default EncryptedBytes encrypt(Bytes decrypted) {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes encrypt(byte[] decrypted, CipherAlgorithm<E, D> cipherAlgorithm) {
        return encrypt(Bytes.of(decrypted), cipherAlgorithm);
    }

    default EncryptedBytes encrypt(byte[] decrypted) {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes encrypt(String input, Charset charset, CipherAlgorithm<E, D> cipherAlgorithm) {
        return encrypt(input.getBytes(charset), cipherAlgorithm);
    }

    default EncryptedBytes encrypt(String input, Charset charset) {
        return encrypt(input, charset, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes encrypt(String input, CipherAlgorithm<E, D> cipherAlgorithm) {
        return encrypt(input, UTF_8, cipherAlgorithm);
    }

    default EncryptedBytes encrypt(String input) {
        return encrypt(input, UTF_8);
    }

}
