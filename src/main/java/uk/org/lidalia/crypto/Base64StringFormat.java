package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Base64StringFormat extends CachedEncodedBase<Bytes, String, Base64StringFormat> implements Encoded<Bytes, String, Base64StringFormat> {

    private final Base64StringFormatEncoder encoder;

    Base64StringFormat(String raw, Pattern regex, Base64StringFormatEncoder encoder) throws InvalidEncoding {
        super(raw, doDecode(raw, regex));
        this.encoder = encoder;
    }

    Base64StringFormat(Bytes decoded, Pattern regex, Base64StringFormatEncoder encoder) {
        super(doEncode(decoded, regex.pattern()), decoded);
        this.encoder = encoder;
    }

    @Override
    public Base64StringFormatEncoder encoder() {
        return encoder;
    }

    private static String doEncode(Bytes decoded, String regexStr) {
        String base64 = decoded.encode().toString();
        String base64EncodedBlock = "\n" + base64.replaceAll("(.{64})", "$1\n") + "\n";
        return regexStr.replace("(?<base64Block>.*)", base64EncodedBlock).replaceAll("\\.\\*", "");
    }

    private static Bytes doDecode(final String raw, Pattern pattern) throws InvalidEncoding {

        Matcher matcher = pattern.matcher(raw);

        if (matcher.matches()) {

            String base64BlockStr = matcher.group("base64Block").replaceAll("\\s+", "");
            return base64.of(base64BlockStr).decode();

        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }
}
