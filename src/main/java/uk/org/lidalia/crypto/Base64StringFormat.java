package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.core.CachedEncodedBase;
import uk.org.lidalia.lang.Bytes;

public class Base64StringFormat extends CachedEncodedBase<Bytes, String> {

    Base64StringFormat(String raw, Bytes decoded) {
        super(raw, decoded);
    }

}
