package uk.org.lidalia.crypto;

public interface CryptoKey<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
        > extends Key {

    CryptoKeyAlgorithm<Encrypt, Decrypt> algorithm();
}
