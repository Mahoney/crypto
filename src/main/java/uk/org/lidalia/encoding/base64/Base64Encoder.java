package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Encoder;

import static java.util.Base64.getEncoder;

public class Base64Encoder implements Encoder<Base64> {

    public static Base64Encoder base64 = new Base64Encoder();

    private Base64Encoder() {}

    @Override
    public Base64 of(String encoded) {
        return new Base64(encoded, this);
    }

    @Override
    public Base64 encode(byte[] decoded) {
        return of(getEncoder().encodeToString(decoded));
    }
}
