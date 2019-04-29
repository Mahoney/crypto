package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.core.CachedEncodedBase;
import uk.org.lidalia.encoding.bytes.EncodedBytes;

public class Base64Url extends CachedEncodedBase<Bytes, String> implements EncodedBytes {

    Base64Url(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

}
