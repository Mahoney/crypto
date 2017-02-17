package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;

import static uk.org.lidalia.crypto.rsa.Pkcs8StringEncoder.pkcs8String;

public class Pkcs8String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs8String> implements Encoded<RsaPrivateKey, String, Pkcs8String> {

    Pkcs8String(String raw, RsaPrivateKey decoded) {
        super(raw, decoded);
    }

    @Override
    public Pkcs8StringEncoder encoder() {
        return pkcs8String;
    }
}
