package uk.org.lidalia.encoding;

public interface EncodedBytes extends Encoded<Bytes, String> {

    Bytes decode();

}
