package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;

import static uk.org.lidalia.crypto.rsa.X509PublicKeyEncoder.x509PublicKey;

public class X509PublicKey extends CachedEncodedBase<RsaPublicKey, Bytes, X509PublicKey> implements Encoded<RsaPublicKey, Bytes, X509PublicKey> {

    X509PublicKey(Bytes raw, RsaPublicKey key) {
        super(raw, key);
    }

    @Override
    public X509PublicKeyEncoder encoder() {
        return x509PublicKey;
    }

}
