package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;

public class Rfc2453PublicKey extends CachedEncodedBase<RsaPublicKey, Bytes, Rfc2453PublicKey> implements Encoded<RsaPublicKey, Bytes, Rfc2453PublicKey> {

    Rfc2453PublicKey(Bytes bytes, RsaPublicKey decoded) {
        super(bytes, decoded);
    }

    @Override
    public Rfc2453PublicKeyEncoder encoder() {
        return Rfc2453PublicKeyEncoder.rfc2453PublicKey;
    }
}
