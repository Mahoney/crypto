package uk.org.lidalia.crypto;

/**
 * A CipherKey is a key used for encryption or decryption.
 *
 * @param <Encrypt> The type of the key used for encrypting in this algorithm
 * @param <Decrypt> The type of the key used for decrypting in this algorithm
 */
public interface CipherKey<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
        > extends Key {

    CipherAlgorithm<Encrypt, Decrypt> algorithm();
}
