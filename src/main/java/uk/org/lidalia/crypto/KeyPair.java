package uk.org.lidalia.crypto;

public interface KeyPair<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > {

    Public publicKey();

    Private privateKey();

    AsymmetricKeyAlgorithm<Public, Private, Pair> algorithm();

    java.security.KeyPair toKeyPair();
}
