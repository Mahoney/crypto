package uk.org.lidalia.encoding;

public interface Encoded<Decoded, Raw, Self extends Encoded<Decoded, Raw, Self>> {

    Encoder<Decoded, Raw, Self> encoder();

    Decoded decode();

    Raw raw();

}
