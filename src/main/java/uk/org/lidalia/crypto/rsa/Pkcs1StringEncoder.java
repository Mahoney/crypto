package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Pkcs1StringEncoder implements Encoder<RsaPrivateKey, String, Pkcs1String> {

    public static final Pkcs1StringEncoder pkcs1String = new Pkcs1StringEncoder();

    private Pkcs1StringEncoder() {}

    @Override
    public Pkcs1String of(String encodedKey) throws InvalidEncoding {
        return new Pkcs1String(encodedKey);
    }

    @Override
    public Pkcs1String encode(RsaPrivateKey decoded) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
