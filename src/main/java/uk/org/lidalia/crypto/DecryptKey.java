package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.lang.Bytes;

public interface DecryptKey<
        E extends EncryptKey<E, D>,
        D extends DecryptKey<E, D>
    > extends CipherKey<E, D> {

    default Bytes decrypt(EncryptedBytes<E, D> encrypted) throws DecryptionFailedException {
        return decrypt(encrypted.bytes(), encrypted.cipher());
    }

    default Bytes decrypt(Bytes encrypted, Cipher<E, D> cipher) throws DecryptionFailedException {
        //noinspection unchecked
        return cipher.decrypt(encrypted, (D) this);
    }

    default Bytes decrypt(Bytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(byte[] encrypted, Cipher<E, D> cipher) throws DecryptionFailedException {
        return decrypt(Bytes.of(encrypted), cipher);
    }

    default Bytes decrypt(byte[] encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(EncodedBytes encrypted, Cipher<E, D> cipher) throws DecryptionFailedException {
        return decrypt(encrypted.decode(), cipher);
    }

    default Bytes decrypt(EncodedBytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }
}
