package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.core.CachedEncodedBase;
import uk.org.lidalia.lang.Bytes;

public class X509PublicKey extends CachedEncodedBase<RsaPublicKey, Bytes> {

    X509PublicKey(Bytes raw, RsaPublicKey key) {
        super(raw, key);
    }

}
