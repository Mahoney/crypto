package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface EncryptKey<E extends EncryptKey<E, D>, D extends DecryptKey<E, D>> extends Key<E, D> {

    default Bytes encrypt(Bytes decrypted, CipherAlgorithm<E, D> cipherAlgorithm) {
        return cipherAlgorithm.encrypt(decrypted, this);
    }

    default Bytes encrypt(Bytes decrypted) {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes encrypt(byte[] decrypted, CipherAlgorithm<E, D> cipherAlgorithm) {
        return encrypt(Bytes.of(decrypted), cipherAlgorithm);
    }

    default Bytes encrypt(byte[] decrypted) {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes encrypt(String input, Charset charset, CipherAlgorithm<E, D> cipherAlgorithm) {
        return encrypt(input.getBytes(charset), cipherAlgorithm);
    }

    default Bytes encrypt(String input, Charset charset) {
        return encrypt(input, charset, algorithm().defaultCipherAlgorithm());
    }

    default Bytes encrypt(String input, CipherAlgorithm<E, D> cipherAlgorithm) {
        return encrypt(input, UTF_8, cipherAlgorithm);
    }

    default Bytes encrypt(String input) {
        return encrypt(input, UTF_8);
    }

}
