package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.EncodedBytes;

public class Hex extends CachedEncodedBase<Bytes, String> implements EncodedBytes {

    Hex(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

}
