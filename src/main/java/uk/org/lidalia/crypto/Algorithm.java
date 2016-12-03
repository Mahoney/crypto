package uk.org.lidalia.crypto;

public interface Algorithm<
        Public extends PublicKey<Public, Private, Pair>,
        Private extends PrivateKey<Public, Private, Pair>,
        Pair extends KeyPair<Public, Private, Pair>
    > {

    String name();

    default Pair generateKeyPair() {
        return generateKeyPair(2048);
    }

    Pair generateKeyPair(int keysize);
}
