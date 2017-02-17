package uk.org.lidalia.encoding;

public abstract class CachedEncodedBase<Decoded, Raw> extends EncodedBase<Decoded, Raw> {

    private final Decoded decoded;

    protected CachedEncodedBase(Raw raw, Decoded decoded) {
        super(raw);
        this.decoded = decoded;
    }

    @Override
    public final Decoded decode() {
        return decoded;
    }

}
