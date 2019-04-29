package uk.org.lidalia.asn1.der;

import uk.org.lidalia.asn1.Asn1;
import uk.org.lidalia.asn1.EncodedAsn1;
import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;

public class Der extends CachedEncodedBase<Asn1, Bytes> implements EncodedAsn1<Bytes> {

    Der(Bytes encoded, Asn1 decoded) {
        super(encoded, decoded);
    }
}
