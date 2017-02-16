package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Rfc2453PublicKeyEncoder implements Encoder<RsaPublicKey, String, Rfc2453PublicKey> {

    public static final Rfc2453PublicKeyEncoder rfc2453PublicKey = new Rfc2453PublicKeyEncoder();

    @Override
    public Rfc2453PublicKey of(String encoded) throws InvalidEncoding {
        return new Rfc2453PublicKey(encoded);
    }

    @Override
    public Rfc2453PublicKey encode(RsaPublicKey rsaPublicKey) {
        return new Rfc2453PublicKey(rsaPublicKey);
    }
}
