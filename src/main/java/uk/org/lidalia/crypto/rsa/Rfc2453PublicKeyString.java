package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;

public class Rfc2453PublicKeyString extends CachedEncodedBase<RsaPublicKey, String> {

    Rfc2453PublicKeyString(String raw, RsaPublicKey rsaPublicKey) {
        super(raw, rsaPublicKey);
    }

}
