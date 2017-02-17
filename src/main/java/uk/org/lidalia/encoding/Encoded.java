package uk.org.lidalia.encoding;

public interface Encoded<Decoded, Raw> {

    Decoded decode();

    Raw raw();

}
