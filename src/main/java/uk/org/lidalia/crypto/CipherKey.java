package uk.org.lidalia.crypto;

public interface CipherKey<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
        > extends Key {

    CipherAlgorithm<Encrypt, Decrypt> algorithm();
}
