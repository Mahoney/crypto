package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

public final class EncryptedBytes {

    private final Bytes bytes;

    public static EncryptedBytes of(byte[] bytes) {
        return of(Bytes.of(bytes));
    }

    public static EncryptedBytes of(Bytes bytes) {
        return new EncryptedBytes(bytes);
    }

    private EncryptedBytes(Bytes bytes) {
        this.bytes = bytes;
    }

    public Bytes bytes() {
        return bytes;
    }
}
