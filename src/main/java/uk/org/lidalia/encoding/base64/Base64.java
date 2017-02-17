package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.EncodedBytes;

public class Base64 extends CachedEncodedBase<Bytes, String> implements EncodedBytes {

    Base64(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

}
