package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.core.ByteEncoder;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.lang.Bytes;

import static java.util.Base64.getEncoder;

public class Base64UrlEncoder implements Encoder<Bytes, String, Base64Url>, ByteEncoder<Base64Url> {

    public static final Base64UrlEncoder base64Url = new Base64UrlEncoder();

    private Base64UrlEncoder() {}

    @Override
    public Base64Url of(String encoded) throws NotABase64UrlEncodedString {
        return new Base64Url(encoded, doDecode(encoded));
    }

    @Override
    public Base64Url encode(Bytes decoded) {
        return new Base64Url(doEncode(decoded), decoded);
    }

    private static Bytes doDecode(String encoded) throws NotABase64UrlEncodedString {
        try {
            return Bytes.of(java.util.Base64.getDecoder().decode(encoded));
        } catch (IllegalArgumentException e) {
            throw NotABase64UrlEncodedString.of(encoded, e);
        }
    }

    private static String doEncode(Bytes decoded) {
        return getEncoder().encodeToString(decoded.array());
    }

}
