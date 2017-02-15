package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.ByteEncoder;
import uk.org.lidalia.encoding.Bytes;

public class Base64Encoder implements ByteEncoder<Base64> {

    public static final Base64Encoder base64 = new Base64Encoder();

    private Base64Encoder() {}

    @Override
    public Base64 of(String encoded) throws NotABase64EncodedString {
        return new Base64(encoded);
    }

    @Override
    public Base64 encode(Bytes decoded) {
        return new Base64(decoded);
    }
}
