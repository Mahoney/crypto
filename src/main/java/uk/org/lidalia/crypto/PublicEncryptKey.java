package uk.org.lidalia.crypto;

public interface PublicEncryptKey<A extends AsymmetricCipherAlgorithm<A>> extends PublicKey<A>, EncryptKey<A> {
}
