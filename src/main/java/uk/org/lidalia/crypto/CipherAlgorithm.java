package uk.org.lidalia.crypto;

/**
 * A CipherAlgorithm is an algorithm used for encryption and decryption.
 * An example would be RSA, or a symmetric encryption algorithm.
 * An example of a KeyAlgorithm that is not a CipherAlgorithm would be DSA - it
 * only signs and verifies.
 *
 * @param <Encrypt> The type of the key used for encrypting in this algorithm
 * @param <Decrypt> The type of the key used for decrypting in this algorithm
 */
public interface CipherAlgorithm<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
        > extends CryptoAlgorithm {

    String name();

    Cipher<Encrypt, Decrypt> defaultCipherAlgorithm();
}
