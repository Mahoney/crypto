package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.asn1.Asn1Sequence;
import uk.org.lidalia.encoding.CachedEncodedBase;

public class Pkcs1Asn1 extends CachedEncodedBase<RsaPrivateKey, Asn1Sequence> {

    Pkcs1Asn1(Asn1Sequence raw, RsaPrivateKey decoded) {
        super(raw, decoded);
    }
}
