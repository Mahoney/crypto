package uk.org.lidalia.crypto;

/**
 * A CipherAlgorithm is an algorithm used for encryption and decryption.
 * An example would be RSA, or a symmetric encryption algorithm.
 * An example of a KeyAlgorithm that is not a CipherAlgorithm would be DSA - it
 * only signs and verifies.
 *
 * @param <Self> The type of this algorithm
 */
public interface CipherAlgorithm<
        Self extends CipherAlgorithm<Self>
        > extends CryptoAlgorithm {

    String name();

    Cipher<Self> defaultCipherAlgorithm();
}
