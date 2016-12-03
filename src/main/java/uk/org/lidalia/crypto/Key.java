package uk.org.lidalia.crypto;

public interface Key<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > extends java.security.Key {

    Algorithm<Public, Private, Pair> algorithm();
}
