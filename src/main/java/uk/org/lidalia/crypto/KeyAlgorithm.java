package uk.org.lidalia.crypto;

public interface KeyAlgorithm<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
    > {

    String name();

    CipherAlgorithm<Encrypt, Decrypt> defaultCipherAlgorithm();
}
