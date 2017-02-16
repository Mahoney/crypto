package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Pattern;

public class Base64StringFormatEncoder<T> implements Encoder<T, String, Base64StringFormat<T>> {

    private final Encoder<T, Bytes, ?> encoder;
    private final Pattern regex;

    public Base64StringFormatEncoder(Encoder<T, Bytes, ?> encoder, Pattern regex) {
        this.encoder = encoder;
        this.regex = regex;
        if (!regex.pattern().contains("(?<base64Block>.*)")) {
            throw new IllegalStateException("Can only be constructed with a pattern containing (?<base64Block>.*)");
        }
    }

    @Override
    public Base64StringFormat<T> of(String raw) throws InvalidEncoding {
        return new Base64StringFormat<>(raw, encoder, regex, this);
    }

    @Override
    public Base64StringFormat<T> encode(T decoded) {
        return new Base64StringFormat<>(decoded, encoder, regex, this);
    }
}
