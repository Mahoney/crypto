package uk.org.lidalia.crypto;

public interface Algorithm<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> {

    String name();

    KeyPair<Public, Private> generateKeyPair();
}
