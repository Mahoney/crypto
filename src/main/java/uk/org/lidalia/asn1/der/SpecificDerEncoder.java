package uk.org.lidalia.asn1.der;

import uk.org.lidalia.asn1.Asn1;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.InvalidEncoding;

interface SpecificDerEncoder {
    Class jvmType();
    Integer derType();
    Bytes encode(Asn1 decoded);
    Asn1 decode(Bytes encoded) throws InvalidEncoding;
}
