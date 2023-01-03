package uk.org.lidalia.crypto;

public interface CipherKeyPair<A extends AsymmetricCipherAlgorithm<A>> extends KeyPair<A> {

    @Override
    PublicEncryptKey<A> publicKey();

    @Override
    PrivateDecryptKey<A> privateKey();

    @Override
    AsymmetricCipherAlgorithm<A> algorithm();
}
