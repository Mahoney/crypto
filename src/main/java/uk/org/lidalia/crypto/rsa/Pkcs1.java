package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Pkcs1 extends CachedEncodedBase<RsaPrivateKey, Bytes> {

    Pkcs1(Bytes raw, RsaPrivateKey decoded) throws InvalidEncoding {
        super(raw, decoded);
    }
}
