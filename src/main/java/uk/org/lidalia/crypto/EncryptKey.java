package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface EncryptKey<A extends CipherAlgorithm<A>> extends CipherKey<A> {

    default EncryptedBytes<A> encrypt(Bytes decrypted, Cipher<A> cipher) throws EncryptionFailedException {
        return cipher.encrypt(decrypted, this);
    }

    default EncryptedBytes<A> encrypt(Bytes decrypted) throws EncryptionFailedException {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes<A> encrypt(byte[] decrypted, Cipher<A> cipher) throws EncryptionFailedException {
        return encrypt(Bytes.of(decrypted), cipher);
    }

    default EncryptedBytes<A> encrypt(byte[] decrypted) throws EncryptionFailedException {
        return encrypt(decrypted, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes<A> encrypt(String input, Charset charset, Cipher<A> cipher) throws EncryptionFailedException {
        return encrypt(input.getBytes(charset), cipher);
    }

    default EncryptedBytes<A> encrypt(String input, Charset charset) throws EncryptionFailedException {
        return encrypt(input, charset, algorithm().defaultCipherAlgorithm());
    }

    default EncryptedBytes<A> encrypt(String input, Cipher<A> cipher) throws EncryptionFailedException {
        return encrypt(input, UTF_8, cipher);
    }

    default EncryptedBytes<A> encrypt(String input) throws EncryptionFailedException {
        return encrypt(input, UTF_8);
    }

}
