package uk.org.lidalia.crypto;

public interface CipherAlgorithm<
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
        > extends CryptoAlgorithm {

    String name();

    Cipher<Encrypt, Decrypt> defaultCipherAlgorithm();
}
