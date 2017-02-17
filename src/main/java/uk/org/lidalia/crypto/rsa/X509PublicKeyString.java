package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;

import static uk.org.lidalia.crypto.rsa.X509PublicKeyStringEncoder.x509PublicKeyString;

public class X509PublicKeyString
        extends CachedEncodedBase<RsaPublicKey, String, X509PublicKeyString>
        implements Encoded<RsaPublicKey, String, X509PublicKeyString> {

    X509PublicKeyString(String raw, RsaPublicKey key) {
        super(raw, key);
    }

    @Override
    public X509PublicKeyStringEncoder encoder() {
        return x509PublicKeyString;
    }

}
