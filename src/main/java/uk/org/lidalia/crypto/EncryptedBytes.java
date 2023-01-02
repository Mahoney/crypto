package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public final class EncryptedBytes {

    private final Bytes bytes;

    public static EncryptedBytes of(byte[] bytes) {
        return of(Bytes.of(bytes));
    }

    public static EncryptedBytes of(Bytes bytes) {
        return new EncryptedBytes(bytes);
    }

    private EncryptedBytes(Bytes bytes) {
        this.bytes = requireNonNull(bytes);
    }

    public Bytes bytes() {
        return bytes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedBytes that = (EncryptedBytes) o;
        return bytes.equals(that.bytes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bytes);
    }

    @Override
    public String toString() {
        return base64.encode(bytes).raw();
    }
}
