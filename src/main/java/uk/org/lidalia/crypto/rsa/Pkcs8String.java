package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.*;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;
import static uk.org.lidalia.crypto.rsa.Pkcs8StringEncoder.pkcs8String;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Pkcs8String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs8String> implements Encoded<RsaPrivateKey, String, Pkcs8String> {

    Pkcs8String(String raw) throws InvalidEncoding {
        super(raw, doDecode(raw));
    }

    Pkcs8String(RsaPrivateKey key) {
        super(doEncode(key), key);
    }

    private static final Base64StringFormatEncoder<RsaPrivateKey> base64StringFormatEncoder = new Base64StringFormatEncoder<>(
            pkcs8,
            Pattern.compile(".*-----BEGIN PRIVATE KEY-----(?<base64Block>.*)-----END PRIVATE KEY-----.*", Pattern.DOTALL),
            true
    );

    private static String doEncode(RsaPrivateKey decoded) {
        return base64StringFormatEncoder.encode(decoded).raw();
    }

    private static RsaPrivateKey doDecode(String raw) throws InvalidEncoding {
        return base64StringFormatEncoder.of(raw).decode();
    }

    @Override
    public Pkcs8StringEncoder encoder() {
        return pkcs8String;
    }

}

class Base64StringFormatEncoder<T> implements Encoder<T, String, Base64StringFormat<T>> {

    private final Encoder<T, Bytes, ?> encoder;
    private final Pattern regex;
    private final boolean multiline;

    Base64StringFormatEncoder(Encoder<T, Bytes, ?> encoder, Pattern regex, boolean multiline) {
        this.encoder = encoder;
        this.regex = regex;
        this.multiline = multiline;
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
        return new Base64StringFormat<>(decoded, encoder, regex, multiline, this);
    }
}

class Base64StringFormat<T> extends CachedEncodedBase<T, String, Base64StringFormat<T>> implements Encoded<T, String, Base64StringFormat<T>> {

    private final Encoder<T, String, Base64StringFormat<T>> encoder;

    Base64StringFormat(String raw, Encoder<T, Bytes, ?> composedEncoder, Pattern regex, Encoder<T, String, Base64StringFormat<T>> encoder) throws InvalidEncoding {
        super(raw, doDecode(raw, regex, composedEncoder));
        this.encoder = encoder;
    }

    Base64StringFormat(T decoded, Encoder<T, Bytes, ?> composedEncoder, Pattern regex, boolean multiline, Encoder<T, String, Base64StringFormat<T>> encoder) {
        super(doEncode(decoded, regex.pattern(), composedEncoder, multiline), decoded);
        this.encoder = encoder;
    }

    @Override
    public Encoder<T, String, Base64StringFormat<T>> encoder() {
        return encoder;
    }

    private static <T, E extends Encoded<T, Bytes, E>> String doEncode(T decoded, String regexStr, Encoder<T, Bytes, E> composedEncoder, boolean multiline) {
        String base64EncodedBlock = composedEncoder.encode(decoded).raw().encode().toString();
        if (multiline) {
            base64EncodedBlock = "\n"+base64EncodedBlock.replaceAll("(.{64})", "$1\n")+"\n";
        }
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
