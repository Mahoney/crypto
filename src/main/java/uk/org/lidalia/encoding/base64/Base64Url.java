package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.EncodedBytesBase;

import static java.util.Base64.getEncoder;
import static uk.org.lidalia.encoding.base64.Base64UrlEncoder.base64Url;

public class Base64Url extends EncodedBytesBase<Base64Url> {

    Base64Url(String encoded) throws NotABase64UrlEncodedString {
        super(encoded, doDecode(encoded), base64Url);
    }

    Base64Url(Bytes decoded) {
        super(doEncode(decoded), decoded, base64Url);
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
