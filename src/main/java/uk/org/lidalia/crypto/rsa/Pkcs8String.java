package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.core.CachedEncodedBase;

public class Pkcs8String extends CachedEncodedBase<RsaPrivateKey, String> {

    Pkcs8String(String raw, RsaPrivateKey decoded) {
        super(raw, decoded);
    }

}
