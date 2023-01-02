package uk.org.lidalia.crypto;

public interface CryptoKeyAlgorithm<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
        > extends KeyAlgorithm {

    String name();

    Cipher<Encrypt, Decrypt> defaultCipherAlgorithm();
}
