package uk.org.lidalia.encoding;

import static java.util.Objects.requireNonNull;

public abstract class CachedEncodedBase<Decoded, Raw> extends EncodedBase<Decoded, Raw> {

    private final Decoded decoded;

    protected CachedEncodedBase(Raw raw, Decoded decoded) {
        super(raw);
        this.decoded = requireNonNull(decoded);
    }

    @Override
    public final Decoded decode() {
        return decoded;
    }

}
