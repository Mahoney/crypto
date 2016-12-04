package uk.org.lidalia.crypto;

public interface Key<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
    > extends java.security.Key {

    KeyAlgorithm<Encrypt, Decrypt> algorithm();
}
