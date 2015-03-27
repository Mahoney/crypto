package uk.org.lidalia.crypto;

public interface KeyPair<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> {

    Public publicKey();

    Private privateKey();

    Algorithm<Public, Private> algorithm();

    java.security.KeyPair toKeyPair();
}
