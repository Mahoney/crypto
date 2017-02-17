package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import static uk.org.lidalia.crypto.rsa.Pkcs1StringEncoder.pkcs1String;

public class Pkcs1String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs1String> implements Encoded<RsaPrivateKey, String, Pkcs1String> {

    Pkcs1String(String raw, RsaPrivateKey decoded) throws InvalidEncoding {
        super(raw, decoded);
    }

    @Override
    public Pkcs1StringEncoder encoder() {
        return pkcs1String;
    }

}
