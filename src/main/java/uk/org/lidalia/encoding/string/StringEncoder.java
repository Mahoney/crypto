package uk.org.lidalia.encoding.string;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

public class StringEncoder implements Encoder<StringWithCharset> {

    public static StringEncoder utf8 = new StringEncoder(UTF_8);
    public static StringEncoder ascii = new StringEncoder(US_ASCII);

    private final Charset charset;

    public StringEncoder(Charset charset) {
        this.charset = charset;
    }

    @Override
    public StringWithCharset of(String encoded) {
        return new StringWithCharset(encoded, this, charset);
    }

    @Override
    public StringWithCharset encode(Bytes decoded) {
        return of(decoded.string(charset));
    }

    public Charset getCharset() {
        return charset;
    }
}
