package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.core.CachedEncodedBase;
import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.lang.Bytes;

public class Hex extends CachedEncodedBase<Bytes, String> implements EncodedBytes {

    Hex(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

}
