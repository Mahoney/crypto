package uk.org.lidalia.asn1.der;

import uk.org.lidalia.asn1.Asn1;
import uk.org.lidalia.asn1.Asn1Integer;
import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.core.InvalidEncoding;

class DerIntegerEncoder implements SpecificDerEncoder {

    @Override
    public Class jvmType() {
        return Asn1Integer.class;
    }

    @Override
    public Integer derType() {
        return 0x02;
    }

    @Override
    public Asn1Integer decode(Bytes bytes) throws InvalidEncoding {
        return Asn1Integer.of(bytes.bigInteger());
    }

    @Override
    public Bytes encode(Asn1 asn1Integer) {
        return Bytes.of(((Asn1Integer)asn1Integer).value());
    }
}
