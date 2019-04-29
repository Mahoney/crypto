package uk.org.lidalia.crypto.core;

import uk.org.lidalia.lang.Bytes;

public interface Key extends java.security.Key {

    KeyAlgorithm algorithm();

    default Bytes bytes() {
        return Bytes.of(getEncoded());
    }
}
