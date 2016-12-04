package uk.org.lidalia.crypto;

public interface AsymmetricKey<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends java.security.Key {

    AsymmetricKeyAlgorithm<Public, Private, Pair> algorithm();
}
