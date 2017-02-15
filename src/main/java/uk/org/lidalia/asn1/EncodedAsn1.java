package uk.org.lidalia.asn1;

import uk.org.lidalia.encoding.Encoded;

public interface EncodedAsn1<RawEncoded, Self extends EncodedAsn1<RawEncoded, Self>> extends Encoded<Asn1, RawEncoded, Self> {

    Asn1Encoder<RawEncoded, Self> encoder();

}
