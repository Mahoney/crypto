package uk.org.lidalia.encoding.core;

import uk.org.lidalia.lang.Bytes;

public interface EncodedBytes extends Encoded<Bytes, String> {

    Bytes decode();

}
