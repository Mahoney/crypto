package uk.org.lidalia.encoding;

import java.util.Objects;

public abstract class EncodedBase<Decoded, Raw, Self extends Encoded<Decoded, Raw, Self>> implements Encoded<Decoded, Raw, Self> {

    private final Raw raw;
    private final Decoded decoded;

    protected EncodedBase(Raw raw, Decoded decoded) {
        this.raw = raw;
        this.decoded = decoded;
    }

    public final String toString() {
        return raw.toString();
    }

    @Override
    public final Decoded decode() {
        return decoded;
    }

    @Override
    public final Raw raw() {
        return raw;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncodedBase that = (EncodedBase) o;
        return Objects.equals(raw, that.raw);
    }

    @Override
    public final int hashCode() {
        return Objects.hashCode(raw);
    }
}
