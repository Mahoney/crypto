package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

public interface Key<A extends CryptoAlgorithm> extends java.security.Key {

    A algorithm();

    default Bytes bytes() {
        return Bytes.of(getEncoded());
    }
}
