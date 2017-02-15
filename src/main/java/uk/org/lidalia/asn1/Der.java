package uk.org.lidalia.asn1;

import uk.org.lidalia.encoding.Bytes;

import static uk.org.lidalia.asn1.DerEncoder.der;

public class Der implements EncodedAsn1<Bytes, Der> {

    private final Bytes rawBytes;

    Der(Bytes rawBytes) {
        this.rawBytes = rawBytes;
    }

    @Override
    public DerEncoder encoder() {
        return der;
    }

    @Override
    public Asn1 decode() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public Bytes raw() {
        return rawBytes;
    }
}
