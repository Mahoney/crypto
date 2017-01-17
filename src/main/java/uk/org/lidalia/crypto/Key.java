package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;

public interface Key extends java.security.Key {

    KeyAlgorithm algorithm();

    default Bytes bytes() {
        return Bytes.of(getEncoded());
    }
}
