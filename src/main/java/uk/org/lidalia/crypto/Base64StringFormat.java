package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;

public class Base64StringFormat extends CachedEncodedBase<Bytes, String, Base64StringFormat> implements Encoded<Bytes, String, Base64StringFormat> {

    private final Base64StringFormatEncoder encoder;

    Base64StringFormat(String raw, Bytes decoded, Base64StringFormatEncoder encoder) {
        super(raw, decoded);
        this.encoder = encoder;
    }

    @Override
    public Base64StringFormatEncoder encoder() {
        return encoder;
    }
}
