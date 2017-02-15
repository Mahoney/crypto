package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.ByteEncoder;
import uk.org.lidalia.encoding.Encoder;

import static java.util.Base64.getEncoder;

public class Base64UrlEncoder implements Encoder<Bytes, String, Base64Url>, ByteEncoder<Base64Url> {

    public static final Base64UrlEncoder base64Url = new Base64UrlEncoder();

    private Base64UrlEncoder() {}

    @Override
    public Base64Url of(String encoded) throws NotABase64UrlEncodedString {
        return new Base64Url(encoded);
    }

    @Override
    public Base64Url encode(Bytes decoded) {
        return new Base64Url(decoded);
    }
}
