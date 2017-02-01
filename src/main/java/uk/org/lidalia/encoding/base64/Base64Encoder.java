package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;

public class Base64Encoder implements Encoder<Base64> {

    public static final Base64Encoder base64 = new Base64Encoder();

    private Base64Encoder() {}

    @Override
    public Base64 of(String encoded) throws NotABase64EncodedString {
        return new Base64(encoded, this);
    }

    @Override
    public Base64 encode(Bytes decoded) {
        try {
            return of(java.util.Base64.getEncoder().encodeToString(decoded.array()));
        } catch (NotABase64EncodedString notABase64EncodedString) {
            throw new AssertionError("It should be impossible to generate a non-base 64 string here", notABase64EncodedString);
        }
    }
}
