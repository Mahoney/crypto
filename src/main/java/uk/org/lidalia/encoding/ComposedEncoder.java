package uk.org.lidalia.encoding;

public class ComposedEncoder<
        Decoded,
        MidFormat,
        RawEncoded
        > implements Encoder<Decoded, RawEncoded, ComposedEncoded<Decoded, RawEncoded>> {

    private final Encoder<Decoded, MidFormat, ? extends Encoded<Decoded, MidFormat, ?>> encoder1;
    private final Encoder<MidFormat, RawEncoded, ? extends Encoded<MidFormat, RawEncoded, ?>> encoder2;

    public ComposedEncoder(
        Encoder<Decoded, MidFormat, ? extends Encoded<Decoded, MidFormat, ?>> encoder1,
        Encoder<MidFormat, RawEncoded, ? extends Encoded<MidFormat, RawEncoded, ?>> encoder2
    ) {
        this.encoder1 = encoder1;
        this.encoder2 = encoder2;
    }

    @Override
    public ComposedEncoded<Decoded, RawEncoded> of(RawEncoded rawEncoded) throws InvalidEncoding {
        return new ComposedEncoded<>(
                encoder1.of(
                        encoder2.of(rawEncoded).decode()
                ).decode(),
                rawEncoded,
                this
        );
    }

    @Override
    public ComposedEncoded<Decoded, RawEncoded> encode(Decoded decoded) {
        return new ComposedEncoded<>(decoded, encoder2.encode(encoder1.encode(decoded).raw()).raw(), this);
    }
}

