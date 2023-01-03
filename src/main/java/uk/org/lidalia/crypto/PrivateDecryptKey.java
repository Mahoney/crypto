package uk.org.lidalia.crypto;

public interface PrivateDecryptKey<A extends AsymmetricCipherAlgorithm<A>> extends PrivateKey<A>, DecryptKey<A> {
}
