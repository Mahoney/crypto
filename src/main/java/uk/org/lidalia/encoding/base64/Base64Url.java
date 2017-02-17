package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.EncodedBytes;

import static uk.org.lidalia.encoding.base64.Base64UrlEncoder.base64Url;

public class Base64Url extends CachedEncodedBase<Bytes, String, Base64Url> implements EncodedBytes<Base64Url> {

    Base64Url(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

    @Override
    public Base64UrlEncoder encoder() {
        return base64Url;
    }
}
