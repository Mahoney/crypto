package uk.org.lidalia.asn1;

import uk.org.lidalia.asn1.der.Der;
import uk.org.lidalia.encoding.Encodable;

import static uk.org.lidalia.asn1.der.DerEncoder.der;

public interface Asn1 extends Encodable<Asn1> {

    default Asn1Integer integer() {
        return (Asn1Integer) this;
    }

    default Asn1Sequence sequence() {
        return (Asn1Sequence) this;
    }

    enum Asn1Class {
        Universal,
        Application,
        Context,
        Private
    }

    enum Tag {

    }

    default Der encode() {
        return encode(der);
    }
}
