package uk.org.lidalia.asn1;

import uk.org.lidalia.encoding.Encodable;

import static uk.org.lidalia.asn1.DerEncoder.der;

public interface Asn1 extends Encodable<Asn1> {

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
