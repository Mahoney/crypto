package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Pkcs1Encoder implements Encoder<RsaPrivateKey, String, Pkcs1> {

    public static final Pkcs1Encoder pkcs1 = new Pkcs1Encoder();

    private Pkcs1Encoder() {}

    @Override
    public Pkcs1 of(String encodedKey) throws InvalidEncoding {
        return new Pkcs1(encodedKey);
    }

    @Override
    public Pkcs1 encode(RsaPrivateKey decoded) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
