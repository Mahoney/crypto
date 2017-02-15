package uk.org.lidalia.encoding;

import java.util.Objects;

public abstract class EncodedBytesBase<T extends EncodedBytes<T>> implements EncodedBytes<T> {

    private final String encoded;
    private final Bytes decoded;
    private final ByteEncoder<T> encoder;

    protected EncodedBytesBase(String encoded, Bytes decoded, ByteEncoder<T> encoder) {
        this.encoded = encoded;
        this.decoded = decoded;
        this.encoder = encoder;
    }

    public final String toString() {
        return encoded;
    }

    @Override
    public final ByteEncoder<T> encoder() {
        return encoder;
    }

    @Override
    public final Bytes decode() {
        return decoded;
    }

    @Override
    public final String raw() {
        return encoded;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncodedBytesBase that = (EncodedBytesBase) o;
        return Objects.equals(encoded, that.encoded);
    }

    @Override
    public final int hashCode() {
        return Objects.hashCode(encoded);
    }
}
