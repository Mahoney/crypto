package uk.org.lidalia.crypto;

public interface KeyPair<A extends AsymmetricCryptoAlgorithm<A>> {

    PublicKey<A> publicKey();

    PrivateKey<A> privateKey();

    AsymmetricCryptoAlgorithm<A> algorithm();

    @SuppressWarnings("unused")
    java.security.KeyPair toJavaKeyPair();
}
