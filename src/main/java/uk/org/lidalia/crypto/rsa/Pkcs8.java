package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.core.CachedEncodedBase;

public class Pkcs8 extends CachedEncodedBase<RsaPrivateKey, Bytes> {

    Pkcs8(Bytes raw, RsaPrivateKey decoded) {
        super(raw, decoded);
    }

}
