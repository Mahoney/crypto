package uk.org.lidalia.crypto;

public interface KeyPair<Public extends PublicKey<Public, Private, KeyP>, Private extends PrivateKey<Public, Private, KeyP>, KeyP extends KeyPair<Public, Private, KeyP>> {

    Public publicKey();

    Private privateKey();

    Algorithm<Public, Private, KeyP> algorithm();

    java.security.KeyPair toKeyPair();
}
