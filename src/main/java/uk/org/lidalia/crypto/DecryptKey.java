package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.lang.Bytes;

public interface DecryptKey<A extends CipherAlgorithm<A>> extends CipherKey<A> {

    default Bytes decrypt(EncryptedBytes<A> encrypted) throws DecryptionFailedException {
        return decrypt(encrypted.bytes(), encrypted.cipher());
    }

    default Bytes decrypt(Bytes encrypted, Cipher<A> cipher) throws DecryptionFailedException {
        return cipher.decrypt(encrypted, this);
    }

    default Bytes decrypt(Bytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(byte[] encrypted, Cipher<A> cipher) throws DecryptionFailedException {
        return decrypt(Bytes.of(encrypted), cipher);
    }

    default Bytes decrypt(byte[] encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }

    default Bytes decrypt(EncodedBytes encrypted, Cipher<A> cipher) throws DecryptionFailedException {
        return decrypt(encrypted.decode(), cipher);
    }

    default Bytes decrypt(EncodedBytes encrypted) throws DecryptionFailedException {
        return decrypt(encrypted, algorithm().defaultCipherAlgorithm());
    }
}
