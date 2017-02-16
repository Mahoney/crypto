package uk.org.lidalia.encoding;

public class ComposedEncoded<Decoded, RawEncoded> extends CachedEncodedBase<Decoded, RawEncoded, ComposedEncoded<Decoded, RawEncoded>> {

    private final Encoder<Decoded, RawEncoded, ComposedEncoded<Decoded, RawEncoded>> encoder;

    ComposedEncoded(Decoded decoded, RawEncoded rawEncoded, Encoder<Decoded, RawEncoded, ComposedEncoded<Decoded, RawEncoded>> encoder) {
        super(rawEncoded, decoded);
        this.encoder = encoder;
    }

    @Override
    public Encoder<Decoded, RawEncoded, ComposedEncoded<Decoded, RawEncoded>> encoder() {
        return encoder;
    }
}
