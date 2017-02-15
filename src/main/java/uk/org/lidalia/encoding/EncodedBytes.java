package uk.org.lidalia.encoding;

public interface EncodedBytes<T extends EncodedBytes<T>> extends Encoded<Bytes, String, T> {

    ByteEncoder<T> encoder();

    Bytes decode();

}
