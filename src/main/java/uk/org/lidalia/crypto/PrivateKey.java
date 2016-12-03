package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface PrivateKey<Public extends PublicKey<Public, Private, KeyP>, Private extends PrivateKey<Public, Private, KeyP>, KeyP extends KeyPair<Public, Private, KeyP>> extends java.security.PrivateKey, Key<Public, Private, KeyP> {

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

    Bytes decrypt(Bytes encrypted) throws DecryptionFailedException;

    default Bytes decrypt(byte[] encrypted) throws DecryptionFailedException {
        return decrypt(Bytes.of(encrypted));
    }

    default Bytes decrypt(Encoded<?> encrypted) throws DecryptionFailedException {
        return decrypt(encrypted.decode());
    }
}
