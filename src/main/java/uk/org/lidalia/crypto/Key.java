package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

public interface Key extends java.security.Key {

    CryptoAlgorithm algorithm();

    default Bytes bytes() {
        return Bytes.of(getEncoded());
    }
}
