package uk.org.lidalia.encoding;

import java.util.Objects;

public abstract class EncodedBase<T extends Encoded<T>> implements Encoded<T> {

    private final String encoded;
    private final Encoder<T> encoder;

    protected EncodedBase(String encoded, Encoder<T> encoder) {
        this.encoded = encoded;
        this.encoder = encoder;
    }

    public final String toString() {
        return encoded;
    }

    @Override
    public final Encoder<T> encoder() {
        return encoder;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncodedBase that = (EncodedBase) o;
        return Objects.equals(encoded, that.encoded);
    }

    @Override
    public final int hashCode() {
        return Objects.hashCode(encoded);
    }
}
