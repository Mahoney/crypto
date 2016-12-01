package uk.org.lidalia.encoding.string;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.EncodedBase;

import java.nio.charset.Charset;

public class StringWithCharset extends EncodedBase<StringWithCharset> {

    private final Charset charset;

    StringWithCharset(String encoded, StringEncoder encoder, Charset charset) {
        super(encoded, encoder);
        this.charset = charset;
    }

    @Override
    public Bytes getDecoded() {
        return Bytes.of(toString().getBytes(charset));
    }
}
