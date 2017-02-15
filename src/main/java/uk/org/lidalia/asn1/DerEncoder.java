package uk.org.lidalia.asn1;

import uk.org.lidalia.encoding.Bytes;

public class DerEncoder implements Asn1Encoder<Bytes, Der> {

    public static final DerEncoder der = new DerEncoder();

    private DerEncoder() {}

    @Override
    public Der encode(Asn1 asn1) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Der of(Bytes encoded) {
        return new Der(encoded);
    }
}
