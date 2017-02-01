package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;

import static java.util.Base64.getEncoder;

public class Base64UrlEncoder implements Encoder<Base64Url> {

    public static final Base64UrlEncoder base64Url = new Base64UrlEncoder();

    private Base64UrlEncoder() {}

    @Override
    public Base64Url of(String encoded) throws NotABase64UrlEncodedString {
        return new Base64Url(encoded, this);
    }

    @Override
    public Base64Url encode(Bytes decoded) {
        try {
            return of(getEncoder().encodeToString(decoded.array()));
        } catch (NotABase64UrlEncodedString notABase64UrlEncodedString) {
            throw new AssertionError("It should be impossible to generate a non-base 64 string here", notABase64UrlEncodedString);
        }
    }
}
