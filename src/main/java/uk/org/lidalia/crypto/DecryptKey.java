package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.lang.Bytes;

public interface DecryptKey<
        E extends EncryptKey<E, D>,
        D extends DecryptKey<E, D>
    > extends CryptoKey<E, D> {

    default Bytes decrypt(EncryptionResult encrypted, CipherAlgorithm cipherAlgorithm) throws DecryptionFailedException {
        return cipherAlgorithm.decrypt(encrypted, this);
    }

    default Bytes decrypt(EncryptionResult encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(Bytes encrypted, CipherAlgorithm cipherAlgorithm) throws DecryptionFailedException {
        return decrypt(EncryptionResult.of(encrypted), cipherAlgorithm);
    }

    default Bytes decrypt(Bytes encrypted) throws DecryptionFailedException {
        return decrypt(EncryptionResult.of(encrypted));
    }

    default Bytes decrypt(byte[] encrypted, CipherAlgorithm<E, D> cipherAlgorithm) throws DecryptionFailedException {
        return decrypt(EncryptionResult.of(encrypted), cipherAlgorithm);
    }

    default Bytes decrypt(byte[] encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(EncodedBytes encrypted, CipherAlgorithm<E, D> cipherAlgorithm) throws DecryptionFailedException {
        return decrypt(encrypted.decode(), cipherAlgorithm);
    }

    default Bytes decrypt(EncodedBytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }
}
