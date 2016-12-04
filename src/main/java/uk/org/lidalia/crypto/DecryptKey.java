package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;

public interface DecryptKey<
        E extends EncryptKey<E, D>,
        D extends DecryptKey<E, D>
    > extends Key<E, D> {

    default Bytes decrypt(Bytes encrypted, CipherAlgorithm<E, D> cipherAlgorithm) throws DecryptionFailedException {
        return cipherAlgorithm.decrypt(encrypted, this);
    }

    default Bytes decrypt(Bytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(byte[] encrypted, CipherAlgorithm<E, D> cipherAlgorithm) throws DecryptionFailedException {
        return decrypt(Bytes.of(encrypted), cipherAlgorithm);
    }

    default Bytes decrypt(byte[] encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(Encoded<?> encrypted, CipherAlgorithm<E, D> cipherAlgorithm) throws DecryptionFailedException {
        return decrypt(encrypted.decode(), cipherAlgorithm);
    }

    default Bytes decrypt(Encoded<?> encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }
}
