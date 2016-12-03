package uk.org.lidalia.encoding;

public interface Encoded<T extends Encoded<T>> {

    Encoder<T> encoder();

    Bytes decode();

}
