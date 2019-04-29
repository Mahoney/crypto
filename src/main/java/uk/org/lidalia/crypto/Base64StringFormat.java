package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;

public class Base64StringFormat extends CachedEncodedBase<Bytes, String> {

    Base64StringFormat(String raw, Bytes decoded) {
        super(raw, decoded);
    }

}
