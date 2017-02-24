package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Base64StringFormatEncoder implements Encoder<Bytes, String, Base64StringFormat> {

    private final Pattern regex;

    public Base64StringFormatEncoder(Pattern regex) {
        this.regex = regex;
        if (!regex.pattern().contains("(?<base64Block>")) {
            throw new IllegalStateException("Can only be constructed with a pattern containing (?<base64Block>.*)");
        }
    }

    @Override
    public Base64StringFormat of(String raw) throws InvalidEncoding {
        return new Base64StringFormat(raw, doDecode(raw));
    }

    @Override
    public Base64StringFormat encode(Bytes decoded) {
        return new Base64StringFormat(doEncode(decoded), decoded);
    }

    private String doEncode(Bytes decoded) {
        String base64 = decoded.encode().toString();
        String base64EncodedBlock = "\n" + base64.replaceAll("(.{64})", "$1\n").trim() + "\n";
        return regex.pattern().replace("(?<base64Block>.*)", base64EncodedBlock).replaceAll("\\.\\*", "");
    }

    private Bytes doDecode(final String raw) throws InvalidEncoding {

        Matcher matcher = regex.matcher(raw);

        if (matcher.matches()) {

            String base64BlockStr = matcher.group("base64Block").replaceAll("\\s+", "");
            return base64.of(base64BlockStr).decode();

        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }
}
