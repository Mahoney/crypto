package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.EncodedBase;

public class Base64Url extends EncodedBase<Base64Url> {

    Base64Url(String encoded, Base64UrlEncoder encoder) {
        super(encoded, encoder);
    }

    @Override
    public Bytes getDecoded() {
        return Bytes.of(java.util.Base64.getUrlDecoder().decode(toString()));
    }
}