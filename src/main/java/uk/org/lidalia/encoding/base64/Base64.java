package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.EncodedBytes;

import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Base64 extends CachedEncodedBase<Bytes, String, Base64> implements EncodedBytes<Base64> {

    Base64(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

    @Override
    public Base64Encoder encoder() {
        return base64;
    }
}
