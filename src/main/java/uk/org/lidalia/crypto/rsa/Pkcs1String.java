package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.crypto.rsa.Pkcs1Encoder.pkcs1;
import static uk.org.lidalia.crypto.rsa.Pkcs1StringEncoder.pkcs1String;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Pkcs1String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs1String> implements Encoded<RsaPrivateKey, String, Pkcs1String> {

    Pkcs1String(String raw) throws InvalidEncoding {
        super(raw, doDecode(raw));
    }

    private static Pattern keyRegex = Pattern.compile(".*-----BEGIN RSA PRIVATE KEY-----(?<base64Key>.*)-----END RSA PRIVATE KEY-----.*", Pattern.DOTALL);

    private static RsaPrivateKey doDecode(String raw) throws InvalidEncoding {

        Matcher keyMatcher = keyRegex.matcher(raw);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key").replaceAll("\\s+", "");
            Bytes keyBytes = base64.of(base64KeyStr).decode();

            return pkcs1.of(keyBytes).decode();

        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }

    @Override
    public Pkcs1StringEncoder encoder() {
        return pkcs1String;
    }

}
