package uk.org.lidalia.encoding;

public interface Encoder<Decoded, RawEncoded, E extends Encoded<Decoded, RawEncoded>> {

    E of(RawEncoded encoded) throws InvalidEncoding;

    E encode(Decoded decoded);

}
