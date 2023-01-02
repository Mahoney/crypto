package uk.org.lidalia.crypto;

public interface KeyPair<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > {

    Public publicKey();

    Private privateKey();

    AsymmetricCryptoAlgorithm<Public, Private, Pair> algorithm();

    @SuppressWarnings("unused")
    java.security.KeyPair toJavaKeyPair();
}
