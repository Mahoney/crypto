package uk.org.lidalia.encoding;

public interface Encodable<Self extends Encodable<Self>> {

    default <RawEncoded, E extends Encoded<Self, RawEncoded, E>> E encode(Encoder<Self, RawEncoded, E> encoder) {
        return encoder.encode((Self) this);
    }

}
