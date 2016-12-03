package uk.org.lidalia.crypto;

public interface Algorithm<Public extends PublicKey<Public, Private, KeyP>, Private extends PrivateKey<Public, Private, KeyP>, KeyP extends KeyPair<Public, Private, KeyP>> {

    String name();

    default KeyP generateKeyPair() {
        return generateKeyPair(2048);
    }

    KeyP generateKeyPair(int keysize);
}
