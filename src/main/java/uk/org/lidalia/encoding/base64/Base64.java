package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.EncodedBytes;

import java.util.regex.Pattern;

import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Base64 extends CachedEncodedBase<Bytes, String, Base64> implements EncodedBytes<Base64> {

    private static final String validBase64Chars = "[a-zA-Z0-9/+]";
    private static final String lastFour = validBase64Chars+"{3}=|"+validBase64Chars+"{2}={2}|"+validBase64Chars+"={3}";
    public static final Pattern legalBase64Encoding = Pattern.compile("("+validBase64Chars+"{4})*("+lastFour+")?");

    Base64(String encoded) throws NotABase64EncodedString {
        super(encoded, doDecode(encoded));
    }

    Base64(Bytes decoded) {
        super(doEncode(decoded), decoded);
    }

    private static Bytes doDecode(String encoded) throws NotABase64EncodedString {
        try {
            return Bytes.of(java.util.Base64.getDecoder().decode(encoded));
        } catch (IllegalArgumentException e) {
            throw NotABase64EncodedString.of(encoded, e);
        }
    }

    private static String doEncode(Bytes decoded) {
        return java.util.Base64.getEncoder().encodeToString(decoded.array());
    }

    @Override
    public Base64Encoder encoder() {
        return base64;
    }
}
