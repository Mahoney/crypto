package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;

public class Pkcs1String extends CachedEncodedBase<RsaPrivateKey, String> {

    Pkcs1String(String raw, RsaPrivateKey decoded) {
        super(raw, decoded);
    }

}
