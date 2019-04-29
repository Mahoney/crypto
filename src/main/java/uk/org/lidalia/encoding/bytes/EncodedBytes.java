package uk.org.lidalia.encoding.bytes;

import uk.org.lidalia.encoding.core.Encoded;
import uk.org.lidalia.lang.Bytes;

public interface EncodedBytes extends Encoded<Bytes, String> {

    Bytes decode();

}
