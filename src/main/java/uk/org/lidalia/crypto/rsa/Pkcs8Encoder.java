package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Pkcs8Encoder implements Encoder<RsaPrivateKey, Bytes, Pkcs8> {

    public static final Pkcs8Encoder pkcs8 = new Pkcs8Encoder();

    private Pkcs8Encoder() {}

    @Override
    public Pkcs8 of(Bytes encodedKey) throws InvalidEncoding {
        return new Pkcs8(encodedKey);
    }

    @Override
    public Pkcs8 encode(RsaPrivateKey decoded) {
        return new Pkcs8(decoded);
    }
}
