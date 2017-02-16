package uk.org.lidalia.crypto;

import uk.org.lidalia.encoding.*;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Base64StringFormat<T> extends CachedEncodedBase<T, String, Base64StringFormat<T>> implements Encoded<T, String, Base64StringFormat<T>> {

    private final Encoder<T, String, Base64StringFormat<T>> encoder;

    Base64StringFormat(String raw, Encoder<T, Bytes, ?> composedEncoder, Pattern regex, Encoder<T, String, Base64StringFormat<T>> encoder) throws InvalidEncoding {
        super(raw, doDecode(raw, regex, composedEncoder));
        this.encoder = encoder;
    }

    Base64StringFormat(T decoded, Encoder<T, Bytes, ?> composedEncoder, Pattern regex, Encoder<T, String, Base64StringFormat<T>> encoder) {
        super(doEncode(decoded, regex.pattern(), composedEncoder), decoded);
        this.encoder = encoder;
    }

    @Override
    public Encoder<T, String, Base64StringFormat<T>> encoder() {
        return encoder;
    }

    private static <T, E extends Encoded<T, Bytes, E>> String doEncode(T decoded, String regexStr, Encoder<T, Bytes, E> composedEncoder) {
        String base64 = composedEncoder.encode(decoded).raw().encode().toString();
        String base64EncodedBlock = "\n" + base64.replaceAll("(.{64})", "$1\n") + "\n";
        return regexStr.replace("(?<base64Block>.*)", base64EncodedBlock).replaceAll("\\.\\*", "");
    }

    private static <T, E extends Encoded<T, Bytes, E>> T doDecode(final String raw, Pattern pattern, Encoder<T, Bytes, E> composedEncoder) throws InvalidEncoding {

        Matcher matcher = pattern.matcher(raw);

        if (matcher.matches()) {

            String base64BlockStr = matcher.group("base64Block").replaceAll("\\s+", "");
            Bytes blockBytes = base64.of(base64BlockStr).decode();

            return composedEncoder.of(blockBytes).decode();

        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }
}
