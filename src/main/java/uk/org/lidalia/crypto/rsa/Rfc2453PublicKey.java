package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;

public class Rfc2453PublicKey extends CachedEncodedBase<RsaPublicKey, Bytes> {

    Rfc2453PublicKey(Bytes bytes, RsaPublicKey decoded) {
        super(bytes, decoded);
    }

}
