package uk.org.lidalia.asn1;

import uk.org.lidalia.encoding.Bytes;

public class Der implements EncodedAsn1<Bytes> {

    private final Bytes rawBytes;

    Der(Bytes rawBytes) {
        this.rawBytes = rawBytes;
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
