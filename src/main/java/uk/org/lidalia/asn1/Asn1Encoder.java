package uk.org.lidalia.asn1;

import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;

public interface Asn1Encoder<RawEncoded, E extends EncodedAsn1<RawEncoded>> extends Encoder<Asn1, RawEncoded, E> {

    E encode(Asn1 asn1);

    E of(RawEncoded encoded) throws InvalidEncoding;
}
