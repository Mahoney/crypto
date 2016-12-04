package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface PrivateKey<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends java.security.PrivateKey, AsymmetricKey<Public, Private, Pair> {

    Bytes signatureFor(
        HashAlgorithm hashAlgorithm,
        Bytes contents
    );

    default Bytes signatureFor(HashAlgorithm hashAlgorithm, byte[] contents) {
        return signatureFor(hashAlgorithm, Bytes.of(contents));
    }

    default Bytes signatureFor(HashAlgorithm hashAlgorithm, String contents, Charset charset) {
        return signatureFor(hashAlgorithm, Bytes.of(contents, charset));
    }

    default Bytes signatureFor(HashAlgorithm hashAlgorithm, String contents) {
        return signatureFor(hashAlgorithm, contents, UTF_8);
    }

    Bytes decrypt(Bytes encrypted, CipherPadding cipherPadding) throws DecryptionFailedException;

    default Bytes decrypt(Bytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherPadding());
    }

    default Bytes decrypt(byte[] encrypted, CipherPadding cipherPadding) throws DecryptionFailedException {
        return decrypt(Bytes.of(encrypted), cipherPadding);
    }

    default Bytes decrypt(byte[] encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherPadding());
    }

    default Bytes decrypt(Encoded<?> encrypted, CipherPadding cipherPadding) throws DecryptionFailedException {
        return decrypt(encrypted.decode(), cipherPadding);
    }

    default Bytes decrypt(Encoded<?> encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherPadding());
    }
}
