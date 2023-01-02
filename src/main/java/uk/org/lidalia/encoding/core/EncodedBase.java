package uk.org.lidalia.encoding.core;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public abstract class EncodedBase<Decoded, Raw> implements Encoded<Decoded, Raw> {

    private final Raw raw;

    protected EncodedBase(Raw raw) {
        this.raw = requireNonNull(raw);
    }

    public String toString() {
        return raw.toString();
    }

    @Override
    public final Raw raw() {
        return raw;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        @SuppressWarnings("rawtypes") EncodedBase that = (EncodedBase) o;
        return Objects.equals(raw, that.raw);
    }

    @Override
    public final int hashCode() {
        return Objects.hashCode(raw);
    }
}
