package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Rfc2453PublicKeyStringEncoder implements Encoder<RsaPublicKey, String, Rfc2453PublicKeyString> {

    public static final Rfc2453PublicKeyStringEncoder rfc2453PublicKeyString = new Rfc2453PublicKeyStringEncoder();

    @Override
    public Rfc2453PublicKeyString of(String encoded) throws InvalidEncoding {
        return new Rfc2453PublicKeyString(encoded);
    }

    @Override
    public Rfc2453PublicKeyString encode(RsaPublicKey rsaPublicKey) {
        return new Rfc2453PublicKeyString(rsaPublicKey);
    }
}
