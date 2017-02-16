package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class X509PublicKeyStringEncoder implements Encoder<RsaPublicKey, String, X509PublicKeyString> {

    public static final X509PublicKeyStringEncoder x509PublicKeyString = new X509PublicKeyStringEncoder();

    private X509PublicKeyStringEncoder() {}

    @Override
    public X509PublicKeyString of(String encodedKey) throws InvalidEncoding {
        return new X509PublicKeyString(encodedKey);
    }

    @Override
    public X509PublicKeyString encode(RsaPublicKey decoded) {
        return new X509PublicKeyString(decoded);
    }
}
