package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.ByteEncoder;
import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.Encoder;

public class Base64Encoder implements Encoder<Bytes, String, Base64>, ByteEncoder<Base64> {

    public static final Base64Encoder base64 = new Base64Encoder();

    private Base64Encoder() {}

    @Override
    public Base64 of(String encoded) throws NotABase64EncodedString {
        return new Base64(encoded, doDecode(encoded));
    }

    @Override
    public Base64 encode(Bytes decoded) {
        return new Base64(doEncode(decoded), decoded);
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
}
