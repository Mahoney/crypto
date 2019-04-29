package uk.org.lidalia.encoding.core;

public interface Encodable<Self extends Encodable<Self>> {

    default <RawEncoded, E extends Encoded<Self, RawEncoded>> E encode(Encoder<Self, RawEncoded, E> encoder) {
        //noinspection unchecked
        return encoder.encode((Self) this);
    }

}
