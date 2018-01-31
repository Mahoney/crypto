package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;

public final class EncryptionResult {

    private final Bytes bytes;

    public static EncryptionResult of(byte[] bytes) {
        return of(Bytes.of(bytes));
    }

    public static EncryptionResult of(Bytes bytes) {
        return new EncryptionResult(bytes);
    }

    private EncryptionResult(Bytes bytes) {
        this.bytes = bytes;
    }

    public Bytes bytes() {
        return bytes;
    }
}
