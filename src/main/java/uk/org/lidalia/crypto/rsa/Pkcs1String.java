package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.InvalidEncoding;

public class Pkcs1String extends CachedEncodedBase<RsaPrivateKey, String> {

    Pkcs1String(String raw, RsaPrivateKey decoded) throws InvalidEncoding {
        super(raw, decoded);
    }

}
