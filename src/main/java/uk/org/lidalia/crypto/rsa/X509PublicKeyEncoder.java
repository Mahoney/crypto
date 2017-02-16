package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

public class X509PublicKeyEncoder implements Encoder<RsaPublicKey, Bytes, X509PublicKey> {

    public static final X509PublicKeyEncoder x509PublicKey = new X509PublicKeyEncoder();

    private X509PublicKeyEncoder() {}

    @Override
    public X509PublicKey of(Bytes encodedKey) throws InvalidEncoding {
        return new X509PublicKey(encodedKey);
    }

    @Override
    public X509PublicKey encode(RsaPublicKey decoded) {
        return new X509PublicKey(decoded);
    }
}
