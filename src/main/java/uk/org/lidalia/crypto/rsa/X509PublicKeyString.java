package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;

public class X509PublicKeyString extends CachedEncodedBase<RsaPublicKey, String> {

    X509PublicKeyString(String raw, RsaPublicKey key) {
        super(raw, key);
    }

}
