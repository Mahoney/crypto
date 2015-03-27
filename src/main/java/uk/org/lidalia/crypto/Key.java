package uk.org.lidalia.crypto;

public interface Key<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> extends java.security.Key {

    Algorithm<Public, Private> algorithm();
}
