package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Pkcs8StringEncoder implements Encoder<RsaPrivateKey, String, Pkcs8String> {

    public static final Pkcs8StringEncoder pkcs8String = new Pkcs8StringEncoder();

    private Pkcs8StringEncoder() {}

    @Override
    public Pkcs8String of(String encodedKey) throws InvalidEncoding {
        return new Pkcs8String(encodedKey);
    }

    @Override
    public Pkcs8String encode(RsaPrivateKey decoded) {
        return new Pkcs8String(decoded);
    }
}
