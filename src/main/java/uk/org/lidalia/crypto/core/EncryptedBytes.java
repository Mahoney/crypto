package uk.org.lidalia.crypto.core;

import uk.org.lidalia.lang.Bytes;

public class EncryptedBytes extends Bytes {

    public static EncryptedBytes of(byte[] bytes) {
        return new EncryptedBytes(bytes);
    }

    public static EncryptedBytes of(Bytes bytes) {
        return of(bytes.array());
    }

    private EncryptedBytes(byte[] bytes) {
        super(bytes);
    }
}
