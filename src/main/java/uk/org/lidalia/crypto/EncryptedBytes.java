package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;

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
