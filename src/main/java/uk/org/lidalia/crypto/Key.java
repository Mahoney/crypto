package uk.org.lidalia.crypto;

import uk.org.lidalia.crypto.rsa.Algorithm;

public interface Key<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> extends java.security.Key {

    Algorithm<Public, Private> algorithm();
}
