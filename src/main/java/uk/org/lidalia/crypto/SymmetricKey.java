package uk.org.lidalia.crypto;

public interface SymmetricKey<A extends CipherAlgorithm<A>>
        extends EncryptKey<A>, DecryptKey<A> {
}
