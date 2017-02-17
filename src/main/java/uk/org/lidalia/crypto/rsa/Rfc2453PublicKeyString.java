package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;

public class Rfc2453PublicKeyString extends CachedEncodedBase<RsaPublicKey, String, Rfc2453PublicKeyString> implements Encoded<RsaPublicKey, String, Rfc2453PublicKeyString> {

    Rfc2453PublicKeyString(String raw, RsaPublicKey rsaPublicKey) {
        super(raw, rsaPublicKey);
    }

    @Override
    public Rfc2453PublicKeyStringEncoder encoder() {
        return Rfc2453PublicKeyStringEncoder.rfc2453PublicKeyString;
    }
}
