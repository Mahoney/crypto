package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.core.CachedEncodedBase;
import uk.org.lidalia.encoding.core.EncodedBytes;
import uk.org.lidalia.lang.Bytes;

public class Base64 extends CachedEncodedBase<Bytes, String> implements EncodedBytes {

    Base64(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

}
