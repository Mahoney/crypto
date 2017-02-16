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

    private static String keyRegexStr = ".*-----BEGIN PRIVATE KEY-----(?<base64Key>.*)-----END PRIVATE KEY-----.*";
    private static Pattern keyRegex = Pattern.compile(keyRegexStr, Pattern.DOTALL);

    private static String doEncode(RsaPrivateKey decoded) {
        return doEncode(decoded, keyRegexStr, pkcs8);
    }

    private static <T, E extends Encoded<T, Bytes, E>> String doEncode(T decoded, String regexStr, Encoder<T, Bytes, E> encoder) {
        String base64EncodedBlock = encoder.encode(decoded).raw().encode().toString().replaceAll("(.{64})", "$1\n");
        return regexStr.replace("(?<base64Key>.*)", "\n"+base64EncodedBlock+"\n");
    }

    private static RsaPrivateKey doDecode(String raw) throws InvalidEncoding {
        return doDecode(raw, keyRegex, pkcs8);
    }

    private static <T, E extends Encoded<T, Bytes, E>> T doDecode(final String raw, Pattern keyRegex, Encoder<T, Bytes, E> encoder) throws InvalidEncoding {

        Matcher keyMatcher = keyRegex.matcher(raw);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key").replaceAll("\\s+", "");
            Bytes keyBytes = base64.of(base64KeyStr).decode();

            return encoder.of(keyBytes).decode();

        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }

    @Override
    public Pkcs8StringEncoder encoder() {
        return pkcs8String;
    }

}
