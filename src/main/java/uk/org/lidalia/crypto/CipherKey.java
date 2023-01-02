package uk.org.lidalia.crypto;

/**
 * A CipherKey is a key used for encryption or decryption.
 *
 * @param <Algorithm> The algorithm of this key
 */
public interface CipherKey<Algorithm extends CipherAlgorithm<Algorithm>> extends Key<Algorithm> {

    Algorithm algorithm();
}
