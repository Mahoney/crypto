package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.EncodedBase;
import uk.org.lidalia.encoding.Encoder;

public class Base64 extends EncodedBase<Base64> {

    Base64(String encoded, Encoder<Base64> encoder) {
        super(encoded, encoder);
    }

    @Override
    public Bytes getDecoded() {
        return Bytes.of(java.util.Base64.getDecoder().decode(toString()));
    }
}