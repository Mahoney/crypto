package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.core.CachedEncodedBase;
import uk.org.lidalia.lang.Bytes;

public class Pkcs1 extends CachedEncodedBase<RsaPrivateKey, Bytes> {

    Pkcs1(Bytes raw, RsaPrivateKey decoded) {
        super(raw, decoded);
    }
}
