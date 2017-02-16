package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Pattern;

public class Base64StringFormatEncoder implements Encoder<Bytes, String, Base64StringFormat> {

    private final Pattern regex;

    public Base64StringFormatEncoder(Pattern regex) {
        this.regex = regex;
        if (!regex.pattern().contains("(?<base64Block>.*)")) {
            throw new IllegalStateException("Can only be constructed with a pattern containing (?<base64Block>.*)");
        }
    }

    @Override
    public Base64StringFormat of(String raw) throws InvalidEncoding {
        return new Base64StringFormat(raw, regex, this);
    }

    @Override
    public Base64StringFormat encode(Bytes decoded) {
        return new Base64StringFormat(decoded, regex, this);
    }
}
