package uk.org.lidalia.encoding.core;

public class ComposedEncoded<Decoded, RawEncoded> extends CachedEncodedBase<Decoded, RawEncoded> {

    ComposedEncoded(Decoded decoded, RawEncoded rawEncoded) {
        super(rawEncoded, decoded);
    }
}
