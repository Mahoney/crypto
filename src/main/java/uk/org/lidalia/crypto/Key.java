package uk.org.lidalia.crypto;

public interface Key<Public extends PublicKey<Public, Private, KeyP>, Private extends PrivateKey<Public, Private, KeyP>, KeyP extends KeyPair<Public, Private, KeyP>> extends java.security.Key {

    Algorithm<Public, Private, KeyP> algorithm();
}
