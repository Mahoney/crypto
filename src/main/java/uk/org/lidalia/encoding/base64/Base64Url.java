package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.EncodedBase;

public class Base64Url extends EncodedBase<Base64Url> {

    Base64Url(String encoded, Base64UrlEncoder encoder) {
        super(encoded, encoder);
    }

    @Override
    public byte[] getDecoded() {
        return java.util.Base64.getUrlDecoder().decode(toString());
    }
}
