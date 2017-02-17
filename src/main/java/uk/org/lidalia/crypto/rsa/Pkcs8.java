package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;

import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;

public class Pkcs8 extends CachedEncodedBase<RsaPrivateKey, Bytes, Pkcs8> implements Encoded<RsaPrivateKey, Bytes, Pkcs8> {

    Pkcs8(Bytes raw, RsaPrivateKey decoded) {
        super(raw, decoded);
    }

    @Override
    public Pkcs8Encoder encoder() {
        return pkcs8;
    }

}
